// Verfy receipts for Node.js agents: the JavaScript twin of the Python `verfy.Recorder`.
//
//   import { Recorder } from "./verfy-node.mjs";
//   const rec = new Recorder({ agent: "refund-bot" });
//   await rec.record("refund", { system: "stripe", kind: "payment", args: { order: "A-1042", amount: 4999 } });
//   const refund = rec.track("refund", async (order, amount) => stripe.refunds.create({ ... }), { kind: "payment" });
//
// Each receipt is `verfy.receipt/1`, signed with Ed25519 over canonical JSON by the shared engine
// (verfy-engine.mjs), chained to the one before, with the arguments and the result kept only as salted hashes. The
// Python CLI checks the same bytes: `verfy ledger verify --ledger ~/.verfy/node/ledger.jsonl --key ~/.verfy/node/key.json`
// (verfy-cli/tests/test_node_sdk.py writes with one and checks with the other, both ways).
//
// The key and ledger live in their own folder, ~/.verfy/node (VERFY_NODE_HOME to move it), in the same format the
// Python CLI uses: `VERFY_HOME=~/.verfy/node verfy team join <code>` enrolls it as its own device and
// `VERFY_HOME=~/.verfy/node verfy sync` uploads its receipts. Requires Node.js 18 or later.

import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createEngine } from "./verfy-engine.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
// next to this file in the npm package; in the repository, the CLI's own data
const DATA = [path.join(HERE, "data"), path.join(HERE, "..", "src", "verfy", "data")].find((d) => fs.existsSync(path.join(d, "patterns.json")));
if (!DATA) throw new Error("verfy: the rule data (patterns.json) is missing next to verfy-node.mjs");
const engine = createEngine(
  JSON.parse(fs.readFileSync(path.join(DATA, "patterns.json"), "utf8")),
  JSON.parse(fs.readFileSync(path.join(DATA, "default_policy.json"), "utf8")),
);

export const RECORD_POLICY = "none";
export const STATUSES = ["ok", "error"];
export const TEXT_MAX = 200;
export const RECEIPT_MAX_BYTES = 12 * 1024;
const KIND = /^[a-z][a-z0-9_-]{0,39}$/;
const LOCK_STALE_MS = 30_000;
const LOCK_WAIT_MS = 10_000;

export class RecordError extends Error {
  constructor(message) {
    super(message);
    this.name = "RecordError";
  }
}

export function defaultHome() {
  return process.env.VERFY_NODE_HOME || path.join(os.homedir(), ".verfy", "node");
}

function text(name, value, { required = false, limit = TEXT_MAX } = {}) {
  if (value === undefined || value === null) value = "";
  if (typeof value !== "string") throw new RecordError(`${name} must be text`);
  if (required && !value.trim()) throw new RecordError(`${name} must not be empty`);
  if (value.length > limit) throw new RecordError(`${name} is longer than ${limit} characters`);
  if (value.includes("\u0000")) throw new RecordError(`${name} must not contain NUL`);
  if (/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(value)) throw new RecordError(`${name} holds a broken character`);
  return value;
}

/** A JSON-like copy of `value`; with strict, anything else is refused, otherwise it is recorded as its type name. */
export function jsonable(value, strict = true, depth = 0) {
  if (depth > 64) throw new RecordError("the value is nested too deeply");
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") return text("a value", value, { limit: Infinity });
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new RecordError("NaN and Infinity cannot be recorded");
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) throw new RecordError("an integer is too large to record exactly");
    return value;
  }
  if (typeof value === "bigint") {
    if (value > BigInt(Number.MAX_SAFE_INTEGER) || value < BigInt(-Number.MAX_SAFE_INTEGER)) throw new RecordError("an integer is too large to record exactly");
    return Number(value);
  }
  if (Array.isArray(value)) return value.map((v) => jsonable(v, strict, depth + 1));
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (v === undefined) continue;
      out[text("a key", k, { limit: Infinity })] = jsonable(v, strict, depth + 1);
    }
    return out;
  }
  if (strict) throw new RecordError(`a ${value?.constructor?.name ?? typeof value} cannot be recorded; pass plain JSON values`);
  return { $type: value?.constructor?.name ?? typeof value };
}

function saltedDigest(value, salt) {
  return engine.digest(salt ? { salt: engine.b64u(salt), value } : value);
}

function loadOrCreateKey(file) {
  const read = async () => {
    const d = JSON.parse(fs.readFileSync(file, "utf8"));
    const key = await engine.keyFromSecret(engine.unb64u(d.secret));
    if (d.public && d.public !== key.public) throw new RecordError(`${file} is corrupt: its public key does not match its secret`);
    key.salt = d.hash_salt ? engine.unb64u(d.hash_salt) : null;
    return key;
  };
  if (fs.existsSync(file)) return read();
  return withLock(file, async () => {
    if (fs.existsSync(file)) return read();
    const key = await engine.generateKey();
    key.salt = new Uint8Array(randomBytes(32));
    const doc = { kty: "Ed25519", kid: key.kid, public: key.public, secret: key.secret, hash_salt: engine.b64u(key.salt) };
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = file + "." + process.pid + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(doc, null, 2) + "\n", { mode: 0o600 });
    fs.renameSync(tmp, file);
    return key;
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const held = new Map();

/** One writer at a time, across processes (a lock directory) and within this one (a promise chain per file). */
async function withLock(file, fn) {
  const before = held.get(file) ?? Promise.resolve();
  let release;
  const mine = new Promise((r) => (release = r));
  const chained = before.then(() => mine);
  held.set(file, chained);
  await before;
  const dir = file + ".jslock";
  const deadline = Date.now() + LOCK_WAIT_MS;
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    for (;;) {
      try {
        fs.mkdirSync(dir);
        break;
      } catch (e) {
        if (e.code !== "EEXIST") throw e;
        try {
          if (Date.now() - fs.statSync(dir).mtimeMs > LOCK_STALE_MS) fs.rmSync(dir, { recursive: true, force: true });
        } catch {
          /* gone already */
        }
        if (Date.now() > deadline) throw new RecordError(`could not lock ${file} within ${LOCK_WAIT_MS / 1000}s`);
        await sleep(5);
      }
    }
    try {
      return await fn();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  } finally {
    release();
    if (held.get(file) === chained) held.delete(file);
  }
}

function lastReceipt(file) {
  if (!fs.existsSync(file)) return null;
  const lines = fs.readFileSync(file, "utf8").split("\n").filter((l) => l.trim());
  if (!lines.length) return null;
  try {
    return JSON.parse(lines[lines.length - 1]);
  } catch (e) {
    throw new RecordError(`the last line of ${file} is not valid JSON: ${e.message}`);
  }
}

export function readLedger(file) {
  if (!fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, "utf8")
    .split("\n")
    .filter((l) => l.trim())
    .map((l, i) => {
      try {
        return JSON.parse(l);
      } catch (e) {
        throw new RecordError(`line ${i + 1} of ${file} is not valid JSON: ${e.message}`);
      }
    });
}

/** Check every signature and link of a ledger file against a public key (base64url). */
export async function verifyLedgerFile(file, publicKey) {
  return engine.verifyLedger(readLedger(file), engine.unb64u(publicKey));
}

export class Recorder {
  constructor({ agent = "agent", home = defaultHome(), session } = {}) {
    this.agent = text("agent", agent, { required: true });
    this.home = home;
    this.session = text("session", session ?? "ses_" + randomBytes(8).toString("hex"), { required: true });
    this.ledgerPath = path.join(home, "ledger.jsonl");
    this.keyPath = path.join(home, "key.json");
    this._key = null;
    this.last = null;
  }

  async key() {
    this._key ??= await loadOrCreateKey(this.keyPath);
    return this._key;
  }

  async kid() {
    return (await this.key()).kid;
  }

  async publicKey() {
    return (await this.key()).public;
  }

  /** The hash a receipt records for arguments or a result: salted with this key's secret salt. */
  async hash(value) {
    return saltedDigest(jsonable(value), (await this.key()).salt);
  }

  /** Sign and append one receipt, and return it. Nothing is written when anything in it is refused. */
  async record(action, { system = "", kind = "other", args = {}, result = null, status = "ok", approvedBy, session } = {}) {
    action = text("action", action, { required: true });
    system = text("system", system);
    if (typeof kind !== "string" || !KIND.test(kind)) throw new RecordError("kind must be one lowercase word (letters, digits, - or _) of at most 40 characters");
    if (!STATUSES.includes(status)) throw new RecordError(`status must be one of ${STATUSES.join(", ")}`);
    const ses = text("session", session ?? this.session, { required: true });
    const a = jsonable(args ?? {});
    const res = result === null || result === undefined ? null : jsonable(result, false);
    const decision = { verdict: "allow", kind, findings: [] };
    if (approvedBy !== undefined) decision.approved_by = text("approvedBy", approvedBy, { required: true, limit: 100 });
    const key = await this.key();
    return withLock(this.ledgerPath, async () => {
      const last = lastReceipt(this.ledgerPath);
      const seq = last ? Number(last.seq) + 1 : 0;
      const prev = last ? await engine.digest(last) : null;
      const body = await engine.buildReceipt({
        seq, prev, agent: this.agent, session: ses, action: { server: system, tool: action, arguments: {} }, decision,
        outcome: { status, result_sha256: res === null ? null : await saltedDigest(res, key.salt) }, policy_sha256: RECORD_POLICY,
      });
      body.action.args_sha256 = await saltedDigest(a, key.salt);
      const receipt = await engine.signReceipt(body, key);
      const line = JSON.stringify(receipt);
      if (Buffer.byteLength(line, "utf8") > RECEIPT_MAX_BYTES) throw new RecordError(`the receipt is over ${RECEIPT_MAX_BYTES} bytes`);
      const fd = fs.openSync(this.ledgerPath, "a");
      try {
        fs.writeSync(fd, line + "\n");
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      this.last = receipt;
      return receipt;
    });
  }

  /**
   * Wrap a function so every call is recorded: its arguments (or what `args(...callArgs)` returns), "ok" with the
   * hash of what it returned, or "error" (and the error is thrown again). A record that cannot be written is logged
   * to the console and never changes what the function does.
   */
  track(action, fn, { system = "", kind = "other", args, recordResult = true, session } = {}) {
    text("action", action, { required: true });
    if (!KIND.test(kind)) throw new RecordError("kind must be one lowercase word (letters, digits, - or _) of at most 40 characters");
    const rec = this;
    const capture = (callArgs) => {
      try {
        return jsonable(args ? args(...callArgs) : { args: callArgs }, false);
      } catch (e) {
        return { $unrecorded: e?.name ?? "Error" };
      }
    };
    const write = async (a, status, result) => {
      try {
        await rec.record(action, { system, kind, args: a, result, status, session });
      } catch (e) {
        console.error(`verfy: could not record ${action}: ${e?.message ?? e}`);
      }
    };
    return async function tracked(...callArgs) {
      const a = capture(callArgs);
      let value;
      try {
        value = await fn.apply(this, callArgs);
      } catch (e) {
        await write(a, "error", { error: e?.name ?? "Error", message: String(e?.message ?? e).slice(0, 2000) });
        throw e;
      }
      await write(a, "ok", recordResult && value !== undefined ? jsonable(value, false) : null);
      return value;
    };
  }

  /** Check this recorder's own ledger. */
  async verify() {
    return verifyLedgerFile(this.ledgerPath, await this.publicKey());
  }
}

export { engine };
