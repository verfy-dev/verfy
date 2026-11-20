// Types for verfy-node.mjs: Verfy receipts for Node.js agents.

export interface Receipt {
  v: "verfy.receipt/1";
  id: string;
  seq: number;
  prev: string | null;
  issued_at: string;
  agent: string;
  session: string;
  action: { server: string; tool: string; kind: string; args_sha256: string };
  decision: { verdict: "allow" | "ask" | "deny"; rules: string[]; policy_sha256: string; approved_by?: string };
  outcome: { status: string; result_sha256: string | null };
  tool_sha256: string | null;
  kid: string;
  sig: string;
}

export interface RecordOptions {
  system?: string;
  kind?: string;
  args?: unknown;
  result?: unknown;
  status?: "ok" | "error";
  approvedBy?: string;
  session?: string;
}

export interface TrackOptions<A extends unknown[]> {
  system?: string;
  kind?: string;
  args?: (...callArgs: A) => unknown;
  recordResult?: boolean;
  session?: string;
}

export interface LedgerCheck {
  ok: boolean;
  count: number;
  head: string | null;
  errors: { index: number; seq: number | null; error: string }[];
}

export class RecordError extends Error {}

export class Recorder {
  constructor(options?: { agent?: string; home?: string; session?: string });
  readonly agent: string;
  readonly home: string;
  readonly session: string;
  readonly ledgerPath: string;
  readonly keyPath: string;
  last: Receipt | null;
  kid(): Promise<string>;
  publicKey(): Promise<string>;
  hash(value: unknown): Promise<string>;
  record(action: string, options?: RecordOptions): Promise<Receipt>;
  track<A extends unknown[], R>(action: string, fn: (...args: A) => R | Promise<R>, options?: TrackOptions<A>): (...args: A) => Promise<R>;
  verify(): Promise<LedgerCheck>;
}

export function defaultHome(): string;
export function jsonable(value: unknown, strict?: boolean): unknown;
export function readLedger(file: string): Receipt[];
export function verifyLedgerFile(file: string, publicKey: string): Promise<LedgerCheck>;
export const RECORD_POLICY: "none";
export const STATUSES: readonly ["ok", "error"];
export const TEXT_MAX: number;
export const RECEIPT_MAX_BYTES: number;
