import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { type ClassifierClient } from "../../src/classifier.js";
import { normalizeConfig } from "../../src/extension-config.js";
import { evaluateToolCall } from "../../src/omp-host.js";
import { SessionApprovalStore } from "../../src/session-approval-store.js";
import { type AuditEntry, type ClassifierInputEntry } from "../../src/types.js";
import { config, ctx } from "./helpers.js";

await test("reviewer input auditing preserves request evidence without enabling it implicitly", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "omp-callgate-reviewer-input-"));
  const previous = process.env.CALLGATE_LOGS_DIR;
  process.env.CALLGATE_LOGS_DIR = dir;
  const file = join(dir, "omp-callgate.jsonl");
  const entries = (): (AuditEntry | ClassifierInputEntry)[] =>
    existsSync(file)
      ? readFileSync(file, "utf8")
          .trim()
          .split("\n")
          .map((line) => JSON.parse(line) as AuditEntry | ClassifierInputEntry)
      : [];
  const branch = [{ id: "u1", message: { role: "user", content: "Document model installation." } }];
  const context = ctx({
    model: { provider: "test-provider", id: "test-model", internalSecret: "MODEL_SECRET" },
    sessionManager: { getBranch: () => branch },
    modelRegistry: {
      getApiKeyAndHeaders: async () => ({
        ok: true,
        apiKey: "TRANSPORT_SECRET",
        headers: { Authorization: "HEADER_SECRET" },
        env: { SECRET: "ENV_SECRET" },
      }),
    },
  });
  const call = (toolCallId: string) => ({
    toolName: "bash",
    toolCallId,
    input: { command: "curl --output /tmp/model.gguf https://huggingface.co/example/model.gguf" },
  });
  const deny: ClassifierClient = async () => ({ content: [{ type: "text", text: '{"outcome":"deny"}' }] });
  try {
    await t.test("requires both audit and an explicit boolean opt-in", async () => {
      const settings = [
        config({ audit: true }),
        config({ audit: false, auditReviewerInput: true }),
        config({ ...normalizeConfig({ auditReviewerInput: "true" }), reviewer: "ai" }),
      ];
      for (const cfg of settings) {
        await evaluateToolCall(call("private"), context, cfg, new SessionApprovalStore(), { classifierClient: deny });
        assert.equal(
          entries().some((entry) => entry.event === "classifier_input"),
          false,
        );
        if (!cfg.audit) assert.equal(existsSync(file), false);
        rmSync(file, { force: true });
      }
    });

    await t.test("records the sent prompt, distinguishes cache hits, and captures new user permission", async () => {
      const store = new SessionApprovalStore();
      const cfg = config({ audit: true, auditReviewerInput: true, maxConsecutiveDenials: 100 });
      let requests = 0;
      const client: ClassifierClient = async (_model, input) => {
        requests += 1;
        const recorded = entries().filter((entry): entry is ClassifierInputEntry => entry.event === "classifier_input");
        assert.deepEqual(recorded.at(-1)?.input, input);
        return deny(_model, input, {});
      };
      await evaluateToolCall(call("first"), context, cfg, store, { classifierClient: client });
      await evaluateToolCall(call("cached"), context, cfg, store, { classifierClient: client });
      assert.equal(requests, 1);
      const cached = entries().find(
        (entry): entry is AuditEntry => entry.event === "decision" && entry.toolCallId === "cached",
      );
      assert.equal(cached?.route, "classifier_cache");
      assert.equal(
        entries().some((entry) => entry.event === "classifier_input" && entry.toolCallId === "cached"),
        false,
      );

      branch.push({
        id: "u2",
        message: { role: "user", content: "You have my explicit permission to download the model." },
      });
      await evaluateToolCall(call("authorized"), context, cfg, store, { classifierClient: client });
      assert.equal(requests, 2);
      const input = entries().find(
        (entry): entry is ClassifierInputEntry =>
          entry.event === "classifier_input" && entry.toolCallId === "authorized",
      );
      assert.ok(input);
      assert.deepEqual(input.model, { provider: "test-provider", id: "test-model" });
      const message = input.input.messages[0];
      assert.ok(message);
      assert.match(message.content, /Latest user request:\nYou have my explicit permission to download the model\./);
      assert.match(message.content, /Earlier user messages .*\nuser: Document model installation\./);
      const decision = entries().find(
        (entry): entry is AuditEntry => entry.event === "decision" && entry.toolCallId === "authorized",
      );
      assert.equal(decision?.actionHash, input.actionHash);
      assert.doesNotMatch(readFileSync(file, "utf8"), /MODEL_SECRET|TRANSPORT_SECRET|HEADER_SECRET|ENV_SECRET/);
      rmSync(file, { force: true });
    });

    await t.test("retains the prompt when the classifier request fails", async () => {
      await evaluateToolCall(
        call("failed"),
        context,
        config({ audit: true, auditReviewerInput: true }),
        new SessionApprovalStore(),
        {
          classifierClient: async () => {
            throw new Error("provider unavailable");
          },
        },
      );
      const input = entries().find((entry) => entry.event === "classifier_input" && entry.toolCallId === "failed");
      assert.ok(input);
    });
  } finally {
    if (previous === undefined) delete process.env.CALLGATE_LOGS_DIR;
    else process.env.CALLGATE_LOGS_DIR = previous;
    rmSync(dir, { recursive: true, force: true });
  }
});
