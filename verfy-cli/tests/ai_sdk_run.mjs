// Used by tests/test_node_sdk.py: tools wrapped by verfy-ai-sdk.mjs, called the way the Vercel AI SDK calls them
// (execute(input, { toolCallId, messages, abortSignal })). When the real `ai` package can be imported (AI_SDK_DIR
// points at a folder with it installed), a full generateText run with its mock model is made too.
// node tests/ai_sdk_run.mjs HOME
import path from "node:path";
import { pathToFileURL } from "node:url";
import { Recorder } from "../js/verfy-node.mjs";
import { withVerfy } from "../js/verfy-ai-sdk.mjs";

const home = process.argv[2];
const rec = new Recorder({ agent: "ai-sdk-bot", home, session: "ses_ai" });
const ran = [];
const tools = withVerfy(
  {
    refund: { description: "Refund an order", execute: async ({ order, amount }) => (ran.push(order), { refunded: amount }) },
    lookup: { description: "Look up an order", execute: async () => { throw new Error("not found"); } },
    clientSide: { description: "Handled in the browser" },
  },
  rec,
  { kinds: { refund: "payment" } },
);
const opts = { toolCallId: "call_1", messages: [], abortSignal: undefined };
const out = { direct: await tools.refund.execute({ order: "A-1", amount: 20 }, opts), untouched: tools.clientSide.execute === undefined };
try {
  await tools.lookup.execute({ order: "B-2" }, opts);
} catch (e) {
  out.rethrown = e.message;
}

if (process.env.AI_SDK_DIR) {
  const req = (m) => import(pathToFileURL(path.join(process.env.AI_SDK_DIR, "node_modules", ...m.split("/"))).href);
  const ai = await req("ai/dist/index.mjs");
  const { MockLanguageModelV2 } = await req("ai/dist/test/index.mjs");
  const { z } = await req("zod/index.js");
  let turn = 0;
  const model = new MockLanguageModelV2({
    doGenerate: async () => {
      turn += 1;
      const usage = { inputTokens: 1, outputTokens: 1, totalTokens: 2 };
      if (turn === 1)
        return { content: [{ type: "tool-call", toolCallId: "c1", toolName: "refund", input: JSON.stringify({ order: "C-3", amount: 5 }) }], finishReason: "tool-calls", usage, warnings: [] };
      return { content: [{ type: "text", text: "done" }], finishReason: "stop", usage, warnings: [] };
    },
  });
  const real = withVerfy({ refund: ai.tool({ description: "Refund", inputSchema: z.object({ order: z.string(), amount: z.number() }), execute: async ({ order, amount }) => (ran.push(order), { refunded: amount }) }) }, rec, { kinds: { refund: "payment" } });
  const res = await ai.generateText({ model, tools: real, prompt: "refund C-3", stopWhen: ai.stepCountIs(3) });
  out.real = res.text;
}
out.ran = ran;
out.check = await rec.verify();
process.stdout.write(JSON.stringify(out) + "\n");
