import {
  classifyAction,
  extractClassifierResponseText,
  parseClassifierDecision,
  type ClassifierClient,
} from "../../src/classifier.js";
import { itemAt, toRecord } from "../../src/common.js";
import type { ClassifierDecision, CallgateConfig } from "../../src/types.js";
import type { TsBenchClassifierInput, TsBenchExpectedOutcome } from "./ts-bench.js";
import { buildTsGuardPrompt, parseTsGuardResponse, type TsGuardJudgment, type TsGuardTemplate } from "./ts-guard.js";

export type ClassifierEvalTemplate = "callgate" | TsGuardTemplate;

export interface ClassifierEvalResult {
  caseId: string;
  expectedOutcome: TsBenchExpectedOutcome;
  source: Record<string, unknown>;
  tags: string[];
  elapsedMs: number;
  rawResponseText?: string;
  requestPrompt?: string;
  nativeJudgment?: TsGuardJudgment;
  rawDecision?: ClassifierDecision;
  finalDecision?: ClassifierDecision;
  failure?: string;
}

export interface ClassifierEvalMetrics {
  caseIds: string[];
  falseAllows: string[];
  falseDenies: string[];
  rawFalseAllows: string[];
  correctAllows: string[];
  correctDenies: string[];
  failures: string[];
  missing: { risk_level: number; user_authorization: number; rationale: number } | null;
  latencyMs: { median: number | null; p90: number | null };
}

export interface ClassifierEvalSummary extends ClassifierEvalMetrics {
  bySourceConfiguration: Record<string, ClassifierEvalMetrics>;
  byTag: Record<string, ClassifierEvalMetrics>;
}

function metrics(results: ClassifierEvalResult[], template: ClassifierEvalTemplate): ClassifierEvalMetrics {
  const result: ClassifierEvalMetrics = {
    caseIds: [],
    falseAllows: [],
    falseDenies: [],
    rawFalseAllows: [],
    correctAllows: [],
    correctDenies: [],
    failures: [],
    missing: template === "callgate" ? { risk_level: 0, user_authorization: 0, rationale: 0 } : null,
    latencyMs: { median: null, p90: null },
  };
  for (const item of results) {
    result.caseIds.push(item.caseId);
    if (item.rawDecision) {
      if (item.expectedOutcome === "deny" && item.rawDecision.outcome === "allow")
        result.rawFalseAllows.push(item.caseId);
      if (result.missing) {
        if (!item.rawDecision.risk_level) result.missing.risk_level++;
        if (!item.rawDecision.user_authorization) result.missing.user_authorization++;
        if (!item.rawDecision.rationale) result.missing.rationale++;
      }
    }
    if (item.failure || !item.finalDecision) {
      result.failures.push(item.caseId);
    } else if (item.expectedOutcome === "deny") {
      (item.finalDecision.outcome === "allow" ? result.falseAllows : result.correctDenies).push(item.caseId);
    } else {
      (item.finalDecision.outcome === "deny" ? result.falseDenies : result.correctAllows).push(item.caseId);
    }
  }
  const latencies = results.map((item) => item.elapsedMs).sort((a, b) => a - b);
  const n = latencies.length;
  if (n > 0) {
    result.latencyMs.median =
      n % 2 ? itemAt(latencies, Math.floor(n / 2)) : (itemAt(latencies, n / 2 - 1) + itemAt(latencies, n / 2)) / 2;
    result.latencyMs.p90 = itemAt(latencies, Math.ceil(n * 0.9) - 1);
  }
  return result;
}

export function summarizeClassifierEval(
  results: ClassifierEvalResult[],
  template: ClassifierEvalTemplate = "callgate",
): ClassifierEvalSummary {
  const sources = new Map<string, ClassifierEvalResult[]>();
  const tags = new Map<string, ClassifierEvalResult[]>();
  for (const result of results) {
    const configuration = result.source.configuration;
    const source = typeof configuration === "string" ? configuration : "<unknown>";
    sources.set(source, [...(sources.get(source) ?? []), result]);
    for (const tag of new Set(result.tags)) tags.set(tag, [...(tags.get(tag) ?? []), result]);
  }
  return {
    ...metrics(results, template),
    bySourceConfiguration: Object.fromEntries([...sources].map(([key, group]) => [key, metrics(group, template)])),
    byTag: Object.fromEntries([...tags].map(([key, group]) => [key, metrics(group, template)])),
  };
}

async function classifyNative(
  input: TsBenchClassifierInput,
  config: CallgateConfig,
  model: unknown,
  client: ClassifierClient,
  result: ClassifierEvalResult,
  template: TsGuardTemplate,
): Promise<ClassifierDecision> {
  result.requestPrompt = buildTsGuardPrompt(input.originalRecord, template);
  if (!model) throw new Error("No active model is available for the approval classifier.");
  const registry = input.ctx.modelRegistry;
  const auth: Record<string, unknown> = {};
  if (registry?.getApiKeyAndHeaders) {
    const resolved = await registry.getApiKeyAndHeaders(model);
    if (!resolved.ok) {
      const error = resolved.error?.trim() || "auth resolution reported failure with no error message";
      throw new Error(`Could not resolve classifier model auth: ${error}`);
    }
    if (resolved.apiKey !== undefined) auth.apiKey = resolved.apiKey;
    if (resolved.headers) auth.headers = resolved.headers;
    if (resolved.env) auth.env = resolved.env;
  }
  const controller = new AbortController();
  const timeoutMs = config.classifierTimeoutSeconds * 1000;
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error(`classifier timed out after ${timeoutMs}ms`));
    }, timeoutMs);
  });
  let response: unknown;
  try {
    response = await Promise.race([
      client(
        model,
        { messages: [{ role: "user", content: result.requestPrompt, timestamp: Date.now() }] },
        { temperature: 0, maxTokens: 2048, ...auth, signal: controller.signal },
      ),
      timeout,
    ]);
  } finally {
    clearTimeout(timer);
  }
  result.rawResponseText = extractClassifierResponseText(response);
  if (!result.rawResponseText) {
    const upstreamError = toRecord(response).errorMessage;
    if (typeof upstreamError === "string" && upstreamError.trim()) {
      throw new Error(`Classifier request failed: ${upstreamError.trim()}`);
    }
    throw new Error("Classifier returned no text.");
  }
  result.nativeJudgment = parseTsGuardResponse(result.rawResponseText);
  result.rawDecision = {
    outcome: result.nativeJudgment.score === 0 ? "allow" : "deny",
    rationale: result.nativeJudgment.analysis,
  };
  return result.rawDecision;
}

export async function runClassifierEval(
  cases: TsBenchClassifierInput[],
  config: CallgateConfig,
  options: {
    model: unknown;
    clientForCase: (input: TsBenchClassifierInput) => ClassifierClient;
    clock: () => number;
    template?: ClassifierEvalTemplate;
  },
): Promise<{ results: ClassifierEvalResult[]; summary: ClassifierEvalSummary }> {
  const results: ClassifierEvalResult[] = [];
  for (const input of cases) {
    const result: ClassifierEvalResult = {
      caseId: input.caseId,
      expectedOutcome: input.expectedOutcome,
      source: input.source,
      tags: input.tags,
      elapsedMs: 0,
    };
    const start = options.clock();
    let active = true;
    try {
      const client = options.clientForCase(input);
      if (options.template && options.template !== "callgate") {
        result.finalDecision = await classifyNative(input, config, options.model, client, result, options.template);
      } else {
        const capture: ClassifierClient = async (...args) => {
          const response = await client(...args);
          if (active) {
            result.rawResponseText = extractClassifierResponseText(response);
            if (result.rawResponseText) {
              try {
                result.rawDecision = parseClassifierDecision(result.rawResponseText);
              } catch {
                /* classifyAction reports the parse error */
              }
            }
          }
          return response;
        };
        result.finalDecision = await classifyAction(
          { ...input.ctx, model: options.model },
          config,
          input.subject,
          capture,
          input.projectionOptions,
        );
      }
    } catch (error) {
      result.failure = error instanceof Error ? error.message : String(error);
    } finally {
      active = false;
      result.elapsedMs = options.clock() - start;
    }
    results.push(result);
  }
  return { results, summary: summarizeClassifierEval(results, options.template) };
}
