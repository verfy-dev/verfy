// Verfy receipts for tools given to the Vercel AI SDK (`ai`, version 4 or later).
//
//   import { generateText, tool } from "ai";
//   import { Recorder } from "./verfy-node.mjs";
//   import { withVerfy } from "./verfy-ai-sdk.mjs";
//
//   const rec = new Recorder({ agent: "support-agent" });
//   const tools = withVerfy({ refund: tool({ description, inputSchema, execute }) }, rec, { kinds: { refund: "payment" } });
//   await generateText({ model, tools, prompt });
//
// Each tool's `execute` is wrapped: every call becomes a signed receipt with the tool's name, the salted hash of its
// input and "ok" with the hash of what it returned, or "error" (and the error is thrown again). Tools without
// `execute` (handled by the client) are passed through unchanged. A receipt that cannot be written is logged and
// never changes what the tool does or returns. The SDK is not a dependency: only the tool objects are touched.

/**
 * @param {Record<string, any>} tools  the tools object passed to generateText / streamText
 * @param {import("./verfy-node.mjs").Recorder} recorder
 * @param {{ system?: string, kind?: string, kinds?: Record<string, string>, recordResult?: boolean }} [options]
 */
export function withVerfy(tools, recorder, { system = "ai-sdk", kind = "other", kinds = {}, recordResult = true } = {}) {
  if (!tools || typeof tools !== "object") throw new TypeError("withVerfy needs the tools object");
  if (!recorder || typeof recorder.track !== "function") throw new TypeError("withVerfy needs a Recorder");
  const out = {};
  for (const [name, t] of Object.entries(tools)) {
    if (!t || typeof t.execute !== "function") {
      out[name] = t;
      continue;
    }
    const execute = recorder.track(name, t.execute, {
      system,
      kind: kinds[name] ?? kind,
      recordResult,
      // the SDK calls execute(input, { toolCallId, messages, abortSignal }): only the input is the tool's argument
      args: (input) => input,
    });
    out[name] = { ...t, execute };
  }
  return out;
}
