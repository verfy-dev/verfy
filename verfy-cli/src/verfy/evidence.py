"""``verfy evidence``: one zip an auditor can take away: what the receipts show, mapped to the controls of SOC 2,
ISO/IEC 42001, AIUC-1 and the EU AI Act, with the ledger itself and how to check it.

The zip holds ``summary.json``, ``controls.json``, ``report.html`` (prints well), ``report.pdf`` (text only, made here
with no dependency), ``ledger.jsonl``, ``public-key.txt``, the policy in force and ``VERIFY.txt``. The mapping says
where Verfy's evidence fits; the auditor decides what satisfies a control. Verfy covers agent tool calls that pass
through its hooks, gateway or SDK, nothing else.
"""

from __future__ import annotations

import html
import io
import json
import zipfile
from collections import Counter
from datetime import datetime, timezone

FRAMEWORKS: dict[str, dict] = {
    "soc2": {"name": "SOC 2 (Trust Services Criteria)", "controls": [
        ("CC6.1", "Logical access security", "Which agent may run which tool and touch which file or host is set in a policy and checked before each call; receipts show the decision."),
        ("CC6.8", "Preventing unauthorized or malicious software", "Changed or new MCP tool definitions are blocked until a person approves them (verfy.lock); risky calls are denied or need approval."),
        ("CC7.2", "Monitoring for anomalies", "Every checked agent call has a signed, hash-chained receipt; denied and asked calls and the rules behind them are counted here."),
        ("CC8.1", "Change management", "Policy changes, tool-lock approvals, stops and emergency access are receipts or policy hashes in the ledger.")]},
    "iso42001": {"name": "ISO/IEC 42001:2023", "controls": [
        ("7.5", "Documented information", "Signed receipts that can be verified offline without trusting Verfy."),
        ("8.1", "Operational planning and control", "One policy enforced before each agent tool call, with approvals for calls that need a person."),
        ("9.1", "Monitoring, measurement, analysis and evaluation", "The counts in this report, for the chosen period."),
        ("A.6.2.8", "AI system recording of event logs", "The ledger: one signed receipt per checked call, chained so an edit, a removal or a reordering shows.")]},
    "aiuc1": {"name": "AIUC-1", "controls": [
        ("B006", "Prevent unauthorized AI agent actions", "Actions outside the policy are blocked or need a person before they run (deny and ask counts below)."),
        ("D003", "Restrict unsafe tool calls", "Shell, file, network, SQL, payment and message calls are checked against rules before they execute."),
        ("A006", "Prevent PII leakage", "Card numbers, IBANs, social security numbers and bulk email addresses in outgoing calls are asked about or blocked (VFY-DLP-*)."),
        ("A008", "Prevent leakage of credentials and secrets", "Keys and tokens in arguments and prompts are blocked or asked about (VFY-SEC-001, VFY-PROMPT-001); MCP output is redacted."),
        ("E009", "Monitor third-party access", "Third-party MCP servers are pinned (verfy.lock) and every call to them is a receipt."),
        ("E015", "Log AI system activity", "The ledger: signed, hash-chained receipts of agent actions, with hashes of arguments rather than the arguments."),
        ("C007", "Flag high risk outputs for human review", "Calls that match an ask rule wait for a person (hooks, Verfy Cloud approvals)."),
        ("E001", "AI failure plan for security breaches", "`verfy stop` halts every agent at once; `verfy incident` exports a signed incident record.")]},
    "eu-ai-act": {"name": "EU AI Act (Regulation (EU) 2024/1689)", "controls": [
        ("Art. 12", "Record-keeping", "Automatic, tamper-evident logs of the agent's tool calls over its lifetime."),
        ("Art. 14", "Human oversight", "Rules that ask stop the agent until a person decides; `verfy stop` interrupts every agent."),
        ("Art. 26(6)", "Deployers keep the logs", "The ledger stays on your computers and in Verfy Cloud if you use it; keep it at least six months.")]},
}


def summarize(receipts: list[dict], verification: dict, since: str | None = None, until: str | None = None) -> dict:
    rows = [r for r in receipts if (not since or r.get("issued_at", "") >= since) and (not until or r.get("issued_at", "") <= until)]
    verdicts = Counter((r.get("decision") or {}).get("verdict", "allow") for r in rows)
    rules = Counter(rule for r in rows for rule in (r.get("decision") or {}).get("rules", []))
    agents = Counter(r.get("agent", "?") for r in rows)
    return {
        "period": {"from": rows[0]["issued_at"] if rows else since, "to": rows[-1]["issued_at"] if rows else until},
        "receipts": len(rows), "verdicts": dict(verdicts), "top_rules": dict(rules.most_common(15)), "agents": dict(agents),
        "approved_by_person": sum(1 for r in rows if (r.get("decision") or {}).get("approved_by")),
        "observe_mode": sum(1 for r in rows if (r.get("decision") or {}).get("would")),
        "emergency_access": sum(1 for r in rows if (r.get("decision") or {}).get("breakglass")),
        "stops": sum(1 for r in rows if (r.get("action") or {}).get("server") == "verfy" and (r.get("action") or {}).get("tool") == "stop"),
        "chain": {"ok": verification.get("ok"), "head": verification.get("head"), "count": verification.get("count"),
                  "errors": verification.get("errors", [])[:20]},
    }


def build(receipts: list[dict], verification: dict, *, kid: str, public: str, policy: dict, frameworks: list[str], version: str,
          ledger_text: str, since: str | None = None, until: str | None = None) -> bytes:
    made = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    s = summarize(receipts, verification, since, until)
    summary = {"v": "verfy.evidence/1", "made_at": made, "verfy": version, "kid": kid, **s}
    controls = [{"framework": FRAMEWORKS[f]["name"], "id": c, "title": t, "evidence": e} for f in frameworks for c, t, e in FRAMEWORKS[f]["controls"]]
    verify_txt = (f"Check this ledger yourself:\n\n  pip install verfy\n  verfy verify --ledger ledger.jsonl --pub {public}\n\n"
                  f"Expected: VERIFIED  {verification.get('count')} receipts, signed by {kid}, chain intact.  head {verification.get('head')}\n\n"
                  "Each receipt holds hashes of the agent's arguments, not the arguments. A receipt that was edited, removed or moved\n"
                  "makes the check fail at that receipt.\n")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("summary.json", json.dumps(summary, indent=2) + "\n")
        z.writestr("controls.json", json.dumps(controls, indent=2) + "\n")
        z.writestr("report.html", _html(summary, controls))
        z.writestr("report.pdf", pdf(_lines(summary, controls)))
        z.writestr("ledger.jsonl", ledger_text)
        z.writestr("public-key.txt", public + "\n")
        z.writestr("policy.json", json.dumps(policy, indent=2, default=str) + "\n")
        z.writestr("VERIFY.txt", verify_txt)
    return buf.getvalue()


def _lines(s: dict, controls: list[dict]) -> list[str]:
    v = s["verdicts"]
    out = ["Verfy evidence pack", "", f"Made {s['made_at']} with Verfy {s['verfy']}, key {s['kid']}",
           f"Period: {s['period']['from']} to {s['period']['to']}", "",
           f"Receipts: {s['receipts']}   allowed {v.get('allow', 0)}   asked {v.get('ask', 0)}   blocked {v.get('deny', 0)}",
           f"Approved by a person: {s['approved_by_person']}   observe mode: {s['observe_mode']}   emergency access: {s['emergency_access']}   stops: {s['stops']}",
           f"Receipt chain: {'intact' if s['chain']['ok'] else 'BROKEN'}   head {s['chain']['head']}", "", "Rules that fired most:"]
    out += [f"  {k}  {n}" for k, n in s["top_rules"].items()] or ["  none"]
    out += ["", "Where this evidence fits (your auditor decides what satisfies each control):"]
    for c in controls:
        out.append("")
        out.append(f"{c['framework']}  {c['id']}  {c['title']}")
        out += ["    " + w for w in _wrap(c["evidence"], 88)]
    out += ["", "Check the ledger: see VERIFY.txt in this zip."]
    return out


def _wrap(text: str, width: int) -> list[str]:
    lines, cur = [], ""
    for w in text.split():
        if len(cur) + len(w) + 1 > width and cur:
            lines.append(cur)
            cur = w
        else:
            cur = (cur + " " + w).strip()
    return lines + ([cur] if cur else [])


def _html(s: dict, controls: list[dict]) -> str:
    E = html.escape
    rows = "".join(f"<tr><td>{E(c['framework'])}</td><td><b>{E(c['id'])}</b> {E(c['title'])}</td><td>{E(c['evidence'])}</td></tr>" for c in controls)
    rules = "".join(f"<li><code>{E(k)}</code> {n}</li>" for k, n in s["top_rules"].items()) or "<li>none</li>"
    v = s["verdicts"]
    return ("<!doctype html><meta charset=utf-8><title>Verfy evidence pack</title><style>body{font:14px/1.5 system-ui,sans-serif;max-width:900px;margin:24px auto;padding:0 16px;color:#111}"
            "table{border-collapse:collapse;width:100%}td{border:1px solid #ccc;padding:6px;vertical-align:top}code{font-size:12px}</style>"
            f"<h1>Verfy evidence pack</h1><p>Made {E(s['made_at'])} with Verfy {E(s['verfy'])}, key <code>{E(s['kid'])}</code>. "
            f"Period {E(str(s['period']['from']))} to {E(str(s['period']['to']))}.</p>"
            f"<p><b>{s['receipts']}</b> receipts: {v.get('allow', 0)} allowed, {v.get('ask', 0)} asked, {v.get('deny', 0)} blocked; "
            f"{s['approved_by_person']} approved by a person; {s['emergency_access']} under emergency access; {s['stops']} stops. "
            f"Receipt chain <b>{'intact' if s['chain']['ok'] else 'BROKEN'}</b>, head <code>{E(str(s['chain']['head']))}</code>.</p>"
            f"<h2>Rules that fired most</h2><ul>{rules}</ul><h2>Where this evidence fits</h2>"
            "<p>Your auditor decides what satisfies each control. Verfy covers agent tool calls that pass through its hooks, gateway or SDK.</p>"
            f"<table>{rows}</table><p>Check the ledger yourself: see VERIFY.txt.</p>")


def pdf(lines: list[str]) -> bytes:
    """A plain text PDF (Helvetica, A4), enough for a report someone prints or attaches. Characters outside Latin-1
    become '?'."""
    per_page = 60
    pages = [lines[i:i + per_page] for i in range(0, max(len(lines), 1), per_page)]
    objs: list[bytes] = []

    def esc(t: str) -> str:
        t = t.encode("latin-1", "replace").decode("latin-1")
        return t.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    n_pages = len(pages)
    # 1 catalog, 2 pages, 3 font, then per page: page object and its content stream
    kids = " ".join(f"{4 + 2 * i} 0 R" for i in range(n_pages))
    objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objs.append(f"<< /Type /Pages /Kids [{kids}] /Count {n_pages} >>".encode())
    objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    for i, page in enumerate(pages):
        body = "BT /F1 10 Tf 13 TL 50 800 Td " + " ".join(f"({esc(t)}) Tj T*" for t in page) + " ET"
        stream = body.encode("latin-1")
        objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents {5 + 2 * i} 0 R >>".encode())
        objs.append(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream")
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, o in enumerate(objs):
        offsets.append(len(out))
        out += f"{i + 1} 0 obj\n".encode() + o + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{off:010d} 00000 n \n".encode() for off in offsets)
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def names(arg: str | None) -> list[str]:
    if not arg or arg == "all":
        return list(FRAMEWORKS)
    out = [x.strip() for x in arg.split(",") if x.strip()]
    bad = [x for x in out if x not in FRAMEWORKS]
    if bad:
        raise ValueError(f"unknown framework(s) {', '.join(bad)}; choose from {', '.join(FRAMEWORKS)} or all")
    return out
