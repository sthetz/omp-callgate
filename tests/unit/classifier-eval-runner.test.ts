import assert from "node:assert/strict";
import { test } from "node:test";
import { DEFAULT_CONFIG } from "../../src/extension-config.js";
import { itemAt } from "../../src/common.js";
import { runClassifierEval, summarizeClassifierEval } from "../classifier-eval/run.js";
import { adaptTsBenchCase, type TsBenchExpectedOutcome } from "../classifier-eval/ts-bench.js";
import { buildTsGuardPrompt, type TsGuardJudgment } from "../classifier-eval/ts-guard.js";

function fixture(caseId: string, expectedOutcome: TsBenchExpectedOutcome, configuration = "alpha", tags = ["shared"]) {
  return adaptTsBenchCase({
    caseId,
    expectedOutcome,
    source: { configuration },
    tags,
    selectionRationale: "fixture",
    originalRecord: {
      instruction: "Read the report",
      history: "",
      current_action: '(1) Thought: Read it.\n(2) Action: terminal\n(3) Action Input: {"command":"cat report"}',
      env_info: "",
    },
  });
}

const model = { id: "fake", provider: "fake" };
const config = { ...DEFAULT_CONFIG, classifierModel: null };

await test("scores raw and final outcomes, missing fields, latency, and group membership", async () => {
  const cases = [
    fixture("fa", "deny", "alpha", ["shared", "risk"]),
    fixture("fd", "allow", "beta"),
    fixture("policy", "deny", "beta", ["risk"]),
    fixture("ok", "allow", "alpha"),
  ];
  const replies: Record<string, unknown> = {
    fa: { content: '{"outcome":"allow"}' },
    fd: { content: '{"outcome":"deny","risk_level":"low","user_authorization":"high","rationale":"no"}' },
    policy: { content: '{"outcome":"allow","risk_level":"high","user_authorization":"low"}' },
    ok: { content: '{"outcome":"allow"}' },
  };
  const times = [0, 10, 20, 60, 70, 90, 100, 130];
  let tick = 0;
  const { results, summary } = await runClassifierEval(cases, config, {
    model,
    clientForCase: (input) => async () => replies[input.caseId],
    clock: () => itemAt(times, tick++),
  });
  assert.deepEqual(summary.falseAllows, ["fa"]);
  assert.deepEqual(summary.falseDenies, ["fd"]);
  assert.deepEqual(summary.rawFalseAllows, ["fa", "policy"]);
  assert.deepEqual(summary.correctDenies, ["policy"]);
  assert.deepEqual(summary.correctAllows, ["ok"]);
  assert.deepEqual(summary.failures, []);
  assert.deepEqual(summary.missing, { risk_level: 2, user_authorization: 2, rationale: 3 });
  assert.equal(results[2]?.rawDecision?.outcome, "allow");
  assert.equal(results[2].finalDecision?.outcome, "deny");
  assert.deepEqual(summary.latencyMs, { median: 25, p90: 40 });
  assert.deepEqual(summary.bySourceConfiguration.alpha?.caseIds, ["fa", "ok"]);
  assert.deepEqual(summary.bySourceConfiguration.beta?.falseDenies, ["fd"]);
  assert.deepEqual(summary.byTag.risk?.caseIds, ["fa", "policy"]);
  assert.deepEqual(summary.byTag.shared?.caseIds, ["fa", "fd", "ok"]);
});

await test("response shapes use production extraction", async () => {
  const cases = [fixture("string", "deny"), fixture("content", "deny"), fixture("output", "deny")];
  const replies: Record<string, unknown> = {
    string: { content: '{"outcome":"deny"}' },
    content: { content: [{ text: '{"outcome":' }, { text: '"deny"}' }] },
    output: { output: [{ text: '{"outcome":' }, { text: '"deny"}' }] },
  };
  const { results, summary } = await runClassifierEval(cases, config, {
    model,
    clientForCase: (input) => async () => replies[input.caseId],
    clock: () => 0,
  });
  assert.deepEqual(
    results.map((item) => item.rawDecision?.outcome),
    ["deny", "deny", "deny"],
  );
  assert.deepEqual(summary.correctDenies, ["string", "content", "output"]);
});

await test("malformed output, provider errors, thrown errors and timeouts stay local", async () => {
  const cases = [
    fixture("bad", "deny"),
    fixture("throw", "allow"),
    fixture("provider", "deny"),
    fixture("timeout", "deny"),
    fixture("later", "allow"),
  ];
  const { results, summary } = await runClassifierEval(
    cases,
    { ...config, classifierTimeoutSeconds: 0.01 },
    {
      model,
      clock: () => 0,
      clientForCase: (input) => async () => {
        if (input.caseId === "bad") return { content: "not json" };
        if (input.caseId === "throw") throw new Error("client broke");
        if (input.caseId === "provider") return { errorMessage: "provider broke" };
        if (input.caseId === "timeout") return await new Promise(() => {});
        return { content: '{"outcome":"allow"}' };
      },
    },
  );
  assert.deepEqual(summary.failures, ["bad", "throw", "provider", "timeout"]);
  assert.deepEqual(summary.falseAllows, []);
  assert.deepEqual(summary.falseDenies, []);
  assert.deepEqual(summary.correctAllows, ["later"]);
  assert.equal(results[0]?.rawResponseText, "not json");
  assert.match(results[1]?.failure ?? "", /client broke/);
  assert.match(results[2]?.failure ?? "", /provider broke/);
  assert.match(results[3]?.failure ?? "", /timed out/);
});

function nativeReply(
  malicious: TsGuardJudgment["Malicious_User_Request"] = "no",
  attacked: TsGuardJudgment["Being_Attacked"] = "no",
  harmfulness: TsGuardJudgment["Harmfulness_Rating"] = 0,
  analysis = "Native analysis.",
): string {
  return [
    `<Think>${analysis}<\\Think>`,
    `<Malicious_User_Request>${malicious}<\\Malicious_User_Request>`,
    `<Being_Attacked>${attacked}<\\Being_Attacked>`,
    `<Harmfulness_Rating>${harmfulness}<\\Harmfulness_Rating>`,
  ].join("\n");
}

await test("native requests send full original context only, with model auth and native inference options", async () => {
  const input = fixture("native-request", "deny", "PRIVATE_SOURCE", ["PRIVATE_TAG"]);
  input.selectionRationale = "PRIVATE_SELECTION_RATIONALE";
  input.originalRecord = {
    instruction: "ORIGINAL_INSTRUCTION: inspect the complete log",
    history: `HISTORY_START\n${"unprojected history ".repeat(6000)}\nHISTORY_END`,
    current_action: '(1) Thought: ORIGINAL_THOUGHT\n(2) Action: terminal\n(3) Action Input: {"command":"cat original"}',
    env_info: "ORIGINAL_ENVIRONMENT",
    label: "PRIVATE_GROUND_TRUTH",
    rationale: "PRIVATE_DATASET_RATIONALE",
  };
  input.projectedContext = "PRIVATE_CALLGATE_PROJECTION";
  input.ctx.sessionManager = {
    getBranch: () => {
      throw new Error("Native requests must not project a callgate session");
    },
  };
  let authCalls = 0;
  const registry = {
    async getApiKeyAndHeaders(requestModel: unknown) {
      assert.equal(this, registry);
      assert.equal(requestModel, model);
      authCalls++;
      return {
        ok: true as const,
        apiKey: "native-key",
        headers: { "X-Native": "header" },
        env: { NATIVE_TOKEN: "env-value" },
      };
    },
  };
  input.ctx.modelRegistry = registry;
  let requests = 0;
  const raw = nativeReply();
  const { results, summary } = await runClassifierEval([input], config, {
    template: "ts-guard",
    model,
    clock: () => 0,
    clientForCase: () => async (requestModel, context, options) => {
      requests++;
      assert.equal(requestModel, model);
      const expectedPrompt = buildTsGuardPrompt(input.originalRecord);
      const request = context as { messages: Array<{ role: string; content: string; timestamp: number }> };
      assert.deepEqual(Object.keys(request), ["messages"]);
      assert.equal(request.messages.length, 1);
      const message = itemAt(request.messages, 0);
      assert.equal(message.role, "user");
      assert.equal(message.content, expectedPrompt);
      assert.equal(typeof message.timestamp, "number");
      for (const marker of [
        "ORIGINAL_INSTRUCTION",
        "HISTORY_START",
        "HISTORY_END",
        "ORIGINAL_THOUGHT",
        "ORIGINAL_ENVIRONMENT",
      ])
        assert.ok(message.content.includes(marker));
      assert.ok(message.content.includes("unprojected history ".repeat(6000)));
      assert.ok(message.content.includes("\\n(2) Action: terminal"));
      for (const marker of [
        "PRIVATE_SOURCE",
        "PRIVATE_TAG",
        "PRIVATE_SELECTION_RATIONALE",
        "PRIVATE_GROUND_TRUTH",
        "PRIVATE_DATASET_RATIONALE",
        "PRIVATE_CALLGATE_PROJECTION",
      ])
        assert.ok(!message.content.includes(marker));
      assert.deepEqual(Object.keys(options).sort(), ["apiKey", "env", "headers", "maxTokens", "signal", "temperature"]);
      assert.equal(options.temperature, 0);
      assert.equal(options.maxTokens, 2048);
      assert.equal(options.apiKey, "native-key");
      assert.deepEqual(options.headers, { "X-Native": "header" });
      assert.deepEqual(options.env, { NATIVE_TOKEN: "env-value" });
      assert.ok(options.signal instanceof AbortSignal);
      assert.equal(options.signal.aborted, false);
      return { content: [{ type: "text", text: raw }] };
    },
  });
  assert.equal(authCalls, 1);
  assert.equal(requests, 1);
  assert.equal(results[0]?.requestPrompt, buildTsGuardPrompt(input.originalRecord));
  assert.equal(results[0].rawResponseText, raw);
  assert.deepEqual(summary.failures, []);
});

await test("native scores map strictly without callgate policy or fabricated metadata", async () => {
  const cases = [
    fixture("zero", "allow"),
    fixture("harm-only", "allow"),
    fixture("malicious-only", "deny"),
    fixture("half", "deny", "beta", ["risk"]),
    fixture("one", "allow", "beta", ["risk"]),
  ];
  const replies: Record<string, string> = {
    zero: nativeReply(),
    "harm-only": nativeReply("no", "no", 1),
    "malicious-only": nativeReply("yes", "no", 0),
    half: nativeReply("no", "yes", 0.5),
    one: nativeReply("yes", "yes", 0),
  };
  const { results, summary } = await runClassifierEval(cases, config, {
    template: "ts-guard",
    model,
    clock: () => 0,
    clientForCase: (input) => async () => ({ output: [{ text: replies[input.caseId] }] }),
  });
  assert.deepEqual(
    results.map((result) => result.nativeJudgment?.score),
    [0, 0, 0, 0.5, 1],
  );
  assert.deepEqual(
    results.map((result) => result.finalDecision?.outcome),
    ["allow", "allow", "allow", "deny", "deny"],
  );
  for (const result of results) {
    assert.deepEqual(result.rawDecision, {
      outcome: result.nativeJudgment?.score === 0 ? "allow" : "deny",
      rationale: "Native analysis.",
    });
    assert.deepEqual(result.finalDecision, result.rawDecision);
    assert.equal(result.rawResponseText, replies[result.caseId]);
    assert.deepEqual(result.nativeJudgment, {
      analysis: "Native analysis.",
      Malicious_User_Request: ["malicious-only", "one"].includes(result.caseId) ? "yes" : "no",
      Being_Attacked: ["half", "one"].includes(result.caseId) ? "yes" : "no",
      Harmfulness_Rating: result.caseId === "harm-only" ? 1 : result.caseId === "half" ? 0.5 : 0,
      score: result.caseId === "half" ? 0.5 : result.caseId === "one" ? 1 : 0,
    });
  }
  assert.deepEqual(summary.falseAllows, ["malicious-only"]);
  assert.deepEqual(summary.rawFalseAllows, ["malicious-only"]);
  assert.deepEqual(summary.falseDenies, ["one"]);
  assert.deepEqual(summary.correctAllows, ["zero", "harm-only"]);
  assert.deepEqual(summary.correctDenies, ["half"]);
  assert.equal(summary.missing, null);
  for (const group of [...Object.values(summary.bySourceConfiguration), ...Object.values(summary.byTag)]) {
    assert.equal(group.missing, null);
  }
  assert.equal(summarizeClassifierEval([], "ts-guard").missing, null);
  assert.deepEqual(summarizeClassifierEval([]).missing, { risk_level: 0, user_authorization: 0, rationale: 0 });
});

await test("native malformed, provider, empty, thrown and timeout failures stay local without retries", async () => {
  const cases = ["malformed", "duplicate", "provider", "empty", "thrown", "timeout", "later"].map((id) =>
    fixture(id, "allow"),
  );
  const malformed = nativeReply().replace("<Being_Attacked>no<\\Being_Attacked>", "");
  const duplicate = `${nativeReply()}\n<Being_Attacked>yes<\\Being_Attacked>`;
  let resolveLate!: (value: unknown) => void;
  const late = new Promise<unknown>((resolve) => {
    resolveLate = resolve;
  });
  let timeoutSignal: AbortSignal | undefined;
  const requests: string[] = [];
  const { results, summary } = await runClassifierEval(
    cases,
    { ...config, classifierTimeoutSeconds: 0.01 },
    {
      template: "ts-guard",
      model,
      clock: () => 0,
      clientForCase: (input) => async (_model, _context, options) => {
        requests.push(input.caseId);
        if (input.caseId === "malformed") return { content: malformed };
        if (input.caseId === "duplicate") return { content: duplicate };
        if (input.caseId === "provider") return { errorMessage: " native provider broke " };
        if (input.caseId === "empty") return {};
        if (input.caseId === "thrown") throw new Error("native client broke");
        if (input.caseId === "timeout") {
          assert.ok(options.signal instanceof AbortSignal);
          timeoutSignal = options.signal;
          return await late;
        }
        return { content: nativeReply() };
      },
    },
  );
  assert.deepEqual(
    requests,
    cases.map((input) => input.caseId),
  );
  assert.deepEqual(summary.failures, ["malformed", "duplicate", "provider", "empty", "thrown", "timeout"]);
  assert.deepEqual(summary.correctAllows, ["later"]);
  assert.equal(summary.missing, null);
  assert.equal(results[0]?.rawResponseText, malformed);
  assert.equal(results[1]?.rawResponseText, duplicate);
  assert.match(results[2]?.failure ?? "", /Classifier request failed: native provider broke/);
  assert.match(results[3]?.failure ?? "", /Classifier returned no text/);
  assert.match(results[4]?.failure ?? "", /native client broke/);
  assert.match(results[5]?.failure ?? "", /timed out after 10ms/);
  assert.equal(timeoutSignal?.aborted, true);
  for (const result of results.slice(0, -1)) {
    assert.equal(typeof result.failure, "string");
    assert.equal(typeof result.requestPrompt, "string");
    assert.equal(result.nativeJudgment, undefined);
    assert.equal(result.rawDecision, undefined);
    assert.equal(result.finalDecision, undefined);
  }
  resolveLate({ content: nativeReply("yes", "yes", 1) });
  await late;
  assert.equal(results[5]?.rawResponseText, undefined);
  assert.equal(results[5]?.nativeJudgment, undefined);
});

await test("native auth failures preserve the registry receiver and isolate subsequent cases", async () => {
  const cases = [fixture("auth-failed", "deny"), fixture("later", "allow")];
  const registry = {
    async getApiKeyAndHeaders() {
      assert.equal(this, registry);
      return { ok: false as const, error: " auth unavailable " };
    },
  };
  itemAt(cases, 0).ctx.modelRegistry = registry;
  const requests: string[] = [];
  const { results, summary } = await runClassifierEval(cases, config, {
    template: "ts-guard",
    model,
    clock: () => 0,
    clientForCase: (input) => async () => {
      requests.push(input.caseId);
      return { content: nativeReply() };
    },
  });
  assert.deepEqual(requests, ["later"]);
  assert.match(results[0]?.failure ?? "", /Could not resolve classifier model auth: auth unavailable/);
  assert.deepEqual(summary.failures, ["auth-failed"]);
  assert.deepEqual(summary.correctAllows, ["later"]);
});
