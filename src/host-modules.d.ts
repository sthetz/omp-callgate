// Packages OMP supplies at runtime: it maps imports of these names to its own
// bundled copies. None are installed for development.
declare module "@oh-my-pi/pi-ai";
declare module "@oh-my-pi/pi-tui";
declare module "@oh-my-pi/pi-tui/driver/session" {
  export function notifyTerminal(message: {
    title: string;
    body: string;
    type: string;
    actions: "focus";
  }): void;
}
declare module "@oh-my-pi/pi-tui/driver/input/keys" {
  export function decodeKey(
    data: string,
    context: { readonly kitty: boolean; readonly backspaceIsCtrl: boolean },
  ): {
    readonly id: string;
    readonly kind: "press" | "repeat" | "release";
    readonly raw: string;
    readonly text?: string;
  } | null;
}
declare module "@oh-my-pi/pi-tui/text/width" {
  export function visibleWidth(text: string): number;
  export function truncate(text: string, width: number): string;
}
