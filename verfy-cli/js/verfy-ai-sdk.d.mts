// Types for verfy-ai-sdk.mjs: Verfy receipts for tools given to the Vercel AI SDK.
import type { Recorder } from "./verfy-node.mjs";

export interface WithVerfyOptions {
  /** recorded as the receipt's action.server (default "ai-sdk") */
  system?: string;
  /** the kind of every tool not named in `kinds` (default "other") */
  kind?: string;
  /** kind per tool name, such as { refund: "payment" } */
  kinds?: Record<string, string>;
  /** record the hash of what each tool returned (default true) */
  recordResult?: boolean;
}

/** The same tools, each `execute` recorded as a signed receipt. Tools without `execute` are passed through. */
export function withVerfy<T extends Record<string, unknown>>(tools: T, recorder: Recorder, options?: WithVerfyOptions): T;
