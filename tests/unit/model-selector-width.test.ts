import assert from "node:assert/strict";
import { DEFAULT_CONFIG } from "../../src/extension-config.js";
import { modelSelectorInternals } from "../../src/model-selector.js";
import type { CallgateConfig, ExtensionContextLike } from "../../src/types.js";
import { test } from "node:test";

const ANSI_SGR_PATTERN = /\x1b\[[0-9;]*m/g;
const graphemeSegmenter = new Intl.Segmenter(undefined, { granularity: "grapheme" });
const extendedPictographicRegex = /\p{Extended_Pictographic}/u;
const markRegex = /^\p{Mark}+$/u;

function testGraphemeWidth(segment: string): number {
  if (extendedPictographicRegex.test(segment)) return 2;
  if (markRegex.test(segment)) return 0;
  const base = segment.normalize("NFC").codePointAt(0) ?? 0;
  return (base >= 0x1100 && base <= 0x115f) ||
    (base >= 0x2e80 && base <= 0xa4cf) ||
    (base >= 0xac00 && base <= 0xd7a3) ||
    (base >= 0xf900 && base <= 0xfaff) ||
    (base >= 0xff00 && base <= 0xff60) ||
    (base >= 0xffe0 && base <= 0xffe6)
    ? 2
    : 1;
}

function testVisibleWidth(text: string): number {
  const clean = text.replace(ANSI_SGR_PATTERN, "");
  let width = 0;
  for (const { segment } of graphemeSegmenter.segment(clean)) {
    width += testGraphemeWidth(segment);
  }
  return width;
}

let truncateCalls = 0;
const piLikeTextUtils = {
  visibleWidth: testVisibleWidth,
  truncateToWidth: (text: string, maxWidth: number): string => {
    truncateCalls += 1;
    if (testVisibleWidth(text) <= maxWidth) return text;
    const clean = text.replace(ANSI_SGR_PATTERN, "");
    const ellipsis = "…";
    const budget = Math.max(0, maxWidth - 1);
    let result = "";
    let width = 0;
    for (const { segment } of graphemeSegmenter.segment(clean)) {
      const segmentWidth = testGraphemeWidth(segment);
      if (width + segmentWidth > budget) break;
      result += segment;
      width += segmentWidth;
    }
    return maxWidth > 0 ? `${result}${ellipsis}` : "";
  },
};

function assertFits(text: string, width: number): void {
  const fitted = modelSelectorInternals.fitLineToWidth(text, width, piLikeTextUtils);
  assert.ok(piLikeTextUtils.visibleWidth(fitted) <= width, `${JSON.stringify(fitted)} exceeds ${width} columns`);
}

await test("the model selector fits every line with the host's width helpers, and the fallback stays within ASCII", async () => {
  assertFits("😀😀", 3);
  assertFits("e\u0301e\u0301e\u0301", 2);
  assertFits("👨‍👩‍👧‍👦👨‍👩‍👧‍👦", 3);
  assertFits("中文😀abc", 6);
  assertFits("\u001b[31m😀中文abcdef\u001b[0m", 8);
  assert.ok(truncateCalls >= 5, "Pi truncateToWidth-compatible helper should be used for overflowing lines");

  for (const sample of ["😀中文", "e\u0301", "👨‍👩‍👧‍👦", "\u001b[31mstyled\u001b[0m"]) {
    const fallback = modelSelectorInternals.fitLineToWidth(sample, 6, modelSelectorInternals.safeFallbackTextUtils);
    const visibleFallback = fallback.replace(ANSI_SGR_PATTERN, "");
    assert.ok(
      /^[\x20-\x7e]*$/.test(visibleFallback),
      `fallback visible text must be printable ASCII: ${JSON.stringify(fallback)}`,
    );
    assert.ok(visibleFallback.length <= 6, `fallback visible text exceeds width: ${JSON.stringify(fallback)}`);
  }

  const hostModule = { visibleWidth: piLikeTextUtils.visibleWidth, truncateToWidth: piLikeTextUtils.truncateToWidth };
  assert.equal(modelSelectorInternals.selectTuiTextUtils(hostModule).visibleWidth, piLikeTextUtils.visibleWidth);
  assert.equal(modelSelectorInternals.selectTuiTextUtils(undefined), modelSelectorInternals.safeFallbackTextUtils);
  assert.equal(modelSelectorInternals.selectTuiTextUtils({}), modelSelectorInternals.safeFallbackTextUtils);

  const config = {
    classifierModel: null,
  } as CallgateConfig;
  const ctx: ExtensionContextLike = {
    cwd: "/tmp/workspace",
    hasUI: true,
    mode: "tui",
    model: { provider: "current-provider", id: "current-model" },
    sessionManager: { getBranch: () => [] },
  };

  const items = [
    {
      value: "review-provider/😀😀😀e\u0301中文👨‍👩‍👧‍👦-very-long-model",
      provider: "review-provider",
      id: "😀😀😀e\u0301中文👨‍👩‍👧‍👦-very-long-model",
      name: "😀 Model e\u0301 中文 👨‍👩‍👧‍👦 with a very long display name",
    },
  ];

  const component = modelSelectorInternals.createSelectorComponent(
    { requestRender: () => {} },
    items,
    ctx,
    config,
    { fg: (_name: string, text: string) => text },
    {},
    piLikeTextUtils,
    () => {},
  ) as { render: (width: number) => string[] };

  const rendered = component.render(20);
  assert.ok(rendered.length > 0);
  for (const line of rendered) {
    assert.ok(
      piLikeTextUtils.visibleWidth(line) <= 20,
      `rendered line exceeds Pi-style width: ${JSON.stringify(line)}`,
    );
  }
  assert.equal(piLikeTextUtils.visibleWidth(rendered[0] ?? ""), 20);
  assert.equal(piLikeTextUtils.visibleWidth(rendered.at(-1) ?? ""), 20);
});

for (const host of ["current", "legacy"] as const) {
  await test(`${host} OMP text exports preserve picker symbols and Unicode model names`, async () => {
    const textUtils = await modelSelectorInternals.loadTuiTextUtils(
      async () => {
        if (host === "legacy") throw new Error("text/width is unavailable");
        return { visibleWidth: piLikeTextUtils.visibleWidth, truncate: piLikeTextUtils.truncateToWidth };
      },
      async () => (host === "legacy" ? piLikeTextUtils : {}),
    );
    const component = modelSelectorInternals.createSelectorComponent(
      {},
      [{ value: "provider/模型😀", provider: "provider", id: "模型😀" }],
      { model: { provider: "provider", id: "模型😀" } },
      DEFAULT_CONFIG,
      {},
      {},
      textUtils,
      () => {},
    );
    const lines = component.render(80);
    const rendered = lines.join("\n");
    for (const symbol of ["↑↓", "•", "→", "✓", "模型😀"]) {
      assert.ok(rendered.includes(symbol), `picker lost ${JSON.stringify(symbol)} with ${host} OMP exports`);
    }
    for (const line of lines) {
      assert.ok(testVisibleWidth(line) <= 80, `picker line exceeds terminal width: ${JSON.stringify(line)}`);
    }
  });
}

await test("unavailable host text modules still give width-safe fallback rendering", async () => {
  const unavailable = async () => {
    throw new Error("host module is unavailable");
  };
  const textUtils = await modelSelectorInternals.loadTuiTextUtils(unavailable, unavailable);
  const rendered = modelSelectorInternals.fitLineToWidth("\u001b[31m↑↓ 中文😀abcdef\u001b[0m", 8, textUtils);
  assert.match(rendered, /^[\x20-\x7e]*$/);
  assert.ok(rendered.length <= 8, `fallback line exceeds terminal width: ${JSON.stringify(rendered)}`);
});
