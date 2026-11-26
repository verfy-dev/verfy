// Types for the shared Verfy engine (verfy-engine.mjs). The engine is a
// line-for-line port of the Python CLI and is tested against the same fixtures.

export type Verdict = "allow" | "ask" | "deny";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  rule: string;
  verdict: Verdict;
  message: string;
  /** set when emergency access (`verfy breakglass`) waived this finding */
  waived?: "breakglass";
}

export interface CheckResult {
  v: string;
  verdict: Verdict;
  kind: string;
  tool: string;
  findings: Finding[];
  /** observe mode (`"mode": "observe"`): what the rules would have answered; nothing was blocked */
  would?: "ask" | "deny";
  /** the emergency access window that let this through */
  breakglass?: string;
}

/** Context a caller may pass to check(). */
export interface CheckContext {
  spent_today?: number;
  spent_month?: number;
  spent_payee_today?: number;
  spent_category_today?: number;
  spent_category_month?: number;
  /** the agent asking (claude-code, cursor, mcp:<server>...), for a stop of one agent */
  agent?: string;
  /** ISO time, for emergency access windows (defaults to now) */
  now?: string;
  untrusted?: string;
  [key: string]: unknown;
}

export interface Action {
  tool: string;
  server?: string;
  arguments?: Record<string, unknown>;
}

export interface ScanFinding {
  rule: string;
  severity: Severity;
  message: string;
  where: string;
}

export interface ToolReport {
  name: string;
  sha256: string;
  pin: "ok" | "new" | "changed" | null;
  capabilities: string[];
  score: number;
  grade: string;
  findings: ScanFinding[];
}

export interface ScanReport {
  v: string;
  server: string;
  score: number;
  grade: string;
  tool_count: number;
  summary: Record<string, number>;
  tools: ToolReport[];
  removed_tools: string[];
}

export interface ConfigReport {
  v: string;
  mode: "static";
  servers: { server: string; transport: "http" | "stdio"; findings: ScanFinding[] }[];
  summary: Record<string, number>;
}

export type Policy = Record<string, unknown>;

export interface Engine {
  version: string;
  PATTERNS: Record<string, unknown>;
  DEFAULT_POLICY: Policy;
  canonical(value: unknown): string;
  digest(value: unknown): Promise<string>;
  loadPolicy(user?: Policy | null, opts?: { home?: string; workspace?: string }): Policy;
  check(action: Action, policy?: Policy | null, context?: CheckContext): CheckResult;
  /** Sort findings and set the verdict with emergency access and observe mode applied (after adding findings). */
  settle(decision: CheckResult, policy: Policy, now?: string): CheckResult;
  /** Why every action is blocked by a stop in the policy, or null. */
  stopped(stop: unknown, agent: string): string | null;
  classify(tool: string, args: Record<string, unknown>): string;
  scan(data: unknown, server?: string, pins?: Record<string, string> | null): Promise<ScanReport>;
  toolPin(tool: Record<string, unknown>): Promise<string>;
  scanSecrets(text: string): { id: string; label: string; severity: Severity; start: number; end: number }[];
  redactValue<T>(value: T): T;
  /** How one MCP server is launched, checked without starting it (the CLI's `verfy scan` config rules, VFY-CFG-001..007). */
  checkServer(name: string, spec: Record<string, unknown>, local?: string[] | null): ScanFinding[];
  configServers(data: unknown): Record<string, Record<string, unknown>>;
  /** The package a stdio server is started from (npx, uvx, ...), also behind a Verfy gateway; `name` is it without the version. */
  packageOf(spec: Record<string, unknown>): { index: number; ecosystem: "npm" | "pypi"; package: string; name: string } | null;
  checkConfig(data: unknown, local?: string[] | null): ConfigReport;
}

export function createEngine(patterns: unknown, defaultPolicy: unknown): Engine;
