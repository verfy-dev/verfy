// Build the npm package of Verfy's JavaScript recorder: node scripts/build-npm.mjs [OUT]   (default dist/npm)
//
// The package is the Node.js recorder (verfy-node.mjs), the Vercel AI SDK wrapper (verfy-ai-sdk.mjs), the shared
// engine (verfy-engine.mjs) and the rule data they read, with their types. Its version is the CLI's, from
// verfy-cli/pyproject.toml. Publishing is a separate step (`npm publish --access public` in OUT, from an npm account
// that owns the @verfy-dev scope); verfy-cli/tests/test_node_sdk.py builds it and records receipts with the result.
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REPO = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const JS = path.join(REPO, "verfy-cli", "js");
const DATA = path.join(REPO, "verfy-cli", "src", "verfy", "data");
const out = path.resolve(process.argv[2] ?? path.join(REPO, "dist", "npm"));

const version = /^version = "([^"]+)"$/m.exec(readFileSync(path.join(REPO, "verfy-cli", "pyproject.toml"), "utf8"))?.[1];
if (!version) throw new Error("no version in verfy-cli/pyproject.toml");

rmSync(out, { recursive: true, force: true });
mkdirSync(path.join(out, "data"), { recursive: true });
const files = ["verfy-node.mjs", "verfy-node.d.mts", "verfy-ai-sdk.mjs", "verfy-ai-sdk.d.mts", "verfy-engine.mjs", "verfy-engine.d.mts"];
for (const f of files) copyFileSync(path.join(JS, f), path.join(out, f));
for (const f of ["patterns.json", "default_policy.json"]) copyFileSync(path.join(DATA, f), path.join(out, "data", f));
copyFileSync(path.join(REPO, "LICENSE"), path.join(out, "LICENSE"));

const pkg = {
  name: "@verfy-dev/receipts",
  version,
  description: "Signed, chained receipts for what an AI agent did (verfy.receipt/1), for Node.js and the Vercel AI SDK",
  license: "MIT",
  type: "module",
  exports: {
    ".": { types: "./verfy-node.d.mts", default: "./verfy-node.mjs" },
    "./ai-sdk": { types: "./verfy-ai-sdk.d.mts", default: "./verfy-ai-sdk.mjs" },
    "./engine": { types: "./verfy-engine.d.mts", default: "./verfy-engine.mjs" },
  },
  files: [...files, "data/", "README.md", "LICENSE"],
  engines: { node: ">=18" },
  sideEffects: false,
  homepage: "https://verfy.dev/docs#frameworks",
  repository: { type: "git", url: "git+https://github.com/verfy-dev/verfy.git", directory: "verfy-cli/js" },
  bugs: "https://github.com/verfy-dev/verfy-releases/issues",
  keywords: ["ai", "agents", "audit", "receipts", "ed25519", "mcp", "verfy"],
};
writeFileSync(path.join(out, "package.json"), JSON.stringify(pkg, null, 2) + "\n");

writeFileSync(
  path.join(out, "README.md"),
  `# @verfy-dev/receipts

Signed, chained receipts for what an AI agent did, from Node.js 18 or later. Each receipt is \`verfy.receipt/1\`: Ed25519
over canonical JSON, chained to the one before, with the arguments and the result kept only as salted hashes. The
Python CLI (\`pip install verfy\`) and Verfy Cloud check the same bytes.

\`\`\`js
import { Recorder } from "@verfy-dev/receipts";
import { withVerfy } from "@verfy-dev/receipts/ai-sdk";

const rec = new Recorder({ agent: "refund-bot" });            // key and ledger in ~/.verfy/node (VERFY_NODE_HOME)
await rec.record("refund", { system: "stripe", kind: "payment", args: { order: "A-1042", amount: 4999 } });
const refund = rec.track("refund", async (order, amount) => { /* ... */ }, { kind: "payment" });
const tools = withVerfy({ refund: tool({ description, inputSchema, execute }) }, rec);   // Vercel AI SDK
console.log(await rec.verify());                              // every signature and link
\`\`\`

Upload the receipts to Verfy Cloud with the CLI: \`VERFY_HOME=~/.verfy/node verfy team join CODE\`, then
\`VERFY_HOME=~/.verfy/node verfy sync\`. The format: https://github.com/verfy-dev/verfy/tree/main/docs/spec

MIT license. https://verfy.dev
`,
);
console.log(`built ${pkg.name}@${version} in ${out}`);
