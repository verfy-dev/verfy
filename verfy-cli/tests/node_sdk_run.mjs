// Used by tests/test_node_sdk.py: write receipts with the Node recorder, or check a ledger with it.
// node tests/node_sdk_run.mjs write HOME  |  node tests/node_sdk_run.mjs verify LEDGER PUBLIC_KEY
import { Recorder, RecordError, verifyLedgerFile } from "../js/verfy-node.mjs";

const [cmd, a, b] = process.argv.slice(2);
if (cmd === "write") {
  const rec = new Recorder({ agent: "node-bot", home: a, session: "ses_node" });
  await rec.record("refund", { system: "stripe", kind: "payment", args: { order: "A-1", amount: 49.99, note: "ünïcode ✓" }, result: { id: "re_1" } });
  const double = rec.track("double", async (x) => x * 2);
  await double(21);
  const fail = rec.track("fail", async () => {
    throw new Error("boom");
  });
  await fail().catch(() => {});
  await Promise.all([1, 2, 3, 4, 5].map((i) => rec.record("parallel", { args: { i } })));
  const refused = [];
  const bad = [
    () => rec.record(""),
    () => rec.record("x", { kind: "Bad Kind" }),
    () => rec.record("x", { status: "maybe" }),
    () => rec.record("x", { args: { n: NaN } }),
    () => rec.record("x", { args: { n: 2 ** 60 } }),
    () => rec.record("x\u0000"),
  ];
  for (const attempt of bad) {
    try {
      await attempt();
      refused.push(false);
    } catch (e) {
      refused.push(e instanceof RecordError);
    }
  }
  const check = await rec.verify();
  process.stdout.write(JSON.stringify({ public: await rec.publicKey(), ok: check.ok, count: check.count, refused }) + "\n");
} else if (cmd === "verify") {
  const res = await verifyLedgerFile(a, b);
  process.stdout.write(JSON.stringify(res) + "\n");
  process.exit(res.ok ? 0 : 1);
} else {
  process.stderr.write("usage: node_sdk_run.mjs write HOME | verify LEDGER PUBLIC_KEY\n");
  process.exit(2);
}
