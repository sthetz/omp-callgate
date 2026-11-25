import assert from "node:assert/strict";
import { test } from "node:test";
import { DEFAULT_CONFIG } from "../../src/extension-config.js";
import { modelSelectorInternals } from "../../src/model-selector.js";
import { canonicalKeybindings } from "../../src/omp-host.js";

// Raw inputs and the corresponding host-decoded events. Decoding belongs to OMP;
// these fixtures exercise the raw/event boundary and the picker's observable behavior.
const events: Record<string, { id: string; kind: string }> = {
  "\u001b[A": { id: "up", kind: "press" },
  "\u001b[B": { id: "down", kind: "press" },
  "\r": { id: "enter", kind: "press" },
  "\n": { id: "enter", kind: "press" },
  "\u001b": { id: "escape", kind: "press" },
  "\u0003": { id: "ctrl+c", kind: "press" },
  "\u000e": { id: "ctrl+n", kind: "press" },
  "\u0010": { id: "ctrl+p", kind: "press" },
  "\t": { id: "tab", kind: "press" },
  "\u0011": { id: "ctrl+q", kind: "press" },
  "\u001b[13;1:3u": { id: "enter", kind: "release" },
};

const defaultBindings: Record<string, string[]> = {
  "tui.select.up": ["up"],
  "tui.select.down": ["down"],
  "tui.select.confirm": ["enter"],
  "tui.select.cancel": ["escape", "ctrl+c"],
};

function picker(api: "raw" | "event", overrides: Record<string, string[]> = {}) {
  const bindings = { ...defaultBindings, ...overrides };
  const host = {
    bindings,
    matches(input: unknown, action: string) {
      const event = api === "raw" ? events[input as string] : (input as { id: string; kind: string });
      return event?.kind !== "release" && (this.bindings[action]?.includes(event?.id ?? "") ?? false);
    },
  };
  const results: Array<string | null | undefined> = [];
  const component = modelSelectorInternals.createSelectorComponent(
    {},
    [
      { value: "provider/first", provider: "provider", id: "first", name: "First Model" },
      { value: "provider/second", provider: "provider", id: "second", name: "Second Model" },
    ],
    {},
    DEFAULT_CONFIG,
    {},
    canonicalKeybindings(host, api === "event" ? (data) => events[data] ?? null : undefined),
    modelSelectorInternals.safeFallbackTextUtils,
    (value) => results.push(value),
  );
  return { component, results };
}

for (const api of ["raw", "event"] as const) {
  await test(`${api} keymap: arrows navigate both ways and Enter selects the highlighted model`, () => {
    const { component, results } = picker(api);
    component.handleInput("\u001b[B");
    component.handleInput("\u001b[B");
    component.handleInput("\u001b[A");
    assert.ok(component.render(120).some((line) => line.includes("Model Name: First Model")));
    component.handleInput("\r");
    assert.deepEqual(results, ["provider/first"]);
  });

  await test(`${api} keymap: navigation wraps and the current-session choice remains selectable`, () => {
    const { component, results } = picker(api);
    component.handleInput("\u001b[A");
    assert.ok(component.render(120).some((line) => line.includes("Model Name: Second Model")));
    component.handleInput("\u001b[B");
    component.handleInput("\n");
    assert.deepEqual(results, [null]);
  });

  await test(`${api} keymap: search still filters the model selected by Enter`, () => {
    const { component, results } = picker(api);
    component.handleInput("provider/second");
    assert.ok(component.render(120).some((line) => line.includes("Model Name: Second Model")));
    component.handleInput("\r");
    assert.deepEqual(results, ["provider/second"]);
  });

  for (const cancel of ["\u001b", "\u0003"]) {
    await test(`${api} keymap: ${cancel === "\u001b" ? "Escape" : "Ctrl+C"} cancels after searching`, () => {
      const { component, results } = picker(api);
      component.handleInput("provider/second");
      component.handleInput(cancel);
      assert.deepEqual(results, [undefined]);
    });
  }
}

await test("event keymap: remapped keys work without re-enabling the default keys", () => {
  const overrides = {
    "tui.select.up": ["ctrl+p"],
    "tui.select.down": ["ctrl+n"],
    "tui.select.confirm": ["tab"],
    "tui.select.cancel": ["ctrl+q"],
  };
  const { component, results } = picker("event", overrides);
  component.handleInput("\u001b[B");
  component.handleInput("\r");
  component.handleInput("\u001b");
  assert.deepEqual(results, []);
  component.handleInput("\u000e");
  component.handleInput("\u000e");
  component.handleInput("\u0010");
  component.handleInput("\t");
  assert.deepEqual(results, ["provider/first"]);

  const cancelled = picker("event", overrides);
  cancelled.component.handleInput("\u0011");
  assert.deepEqual(cancelled.results, [undefined]);
});

await test("event keymap: key releases do not confirm a model", () => {
  const { component, results } = picker("event");
  component.handleInput("\u001b[13;1:3u");
  assert.deepEqual(results, []);
  component.handleInput("\r");
  assert.deepEqual(results, [null]);
});
