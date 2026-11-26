"""``verfy today``: what your agents did today, in plain words, from the signed receipts on this computer.

No model writes this: it counts receipts and lists what was blocked, asked about, let through by emergency access
or would have been blocked in observe mode. The receipts hold hashes of arguments, so the summary names tools and
rules, never what was typed.
"""

from __future__ import annotations

from collections import Counter
from datetime import date, datetime, timezone
from typing import Any


def _local(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone()
    except (TypeError, ValueError):
        return None


def summarize(receipts: list[dict], day: date | None = None) -> dict:
    day = day or datetime.now(timezone.utc).astimezone().date()
    rows = []
    for r in receipts:
        t = _local(str(r.get("issued_at", "")))
        if t is not None and t.date() == day:
            rows.append((t, r))
    verdicts: Counter = Counter()
    tools: Counter = Counter()
    agents: Counter = Counter()
    blocked, asked, would, waived, control = [], [], [], [], []
    for t, r in rows:
        a, d = r.get("action") or {}, r.get("decision") or {}
        if a.get("server") == "verfy" and r.get("agent") == "person":
            control.append({"time": t.strftime("%H:%M"), "what": a.get("tool", "")})
            continue
        v = d.get("verdict", "allow")
        verdicts[v] += 1
        tools[a.get("tool", "?")] += 1
        agents[r.get("agent", "?")] += 1
        item = {"time": t.strftime("%H:%M"), "agent": r.get("agent", ""), "tool": a.get("tool", ""), "rules": d.get("rules", []), "seq": r.get("seq")}
        if v == "deny":
            blocked.append(item)
        elif v == "ask":
            asked.append({**item, "approved_by": d.get("approved_by")})
        if d.get("would"):
            would.append({**item, "would": d["would"]})
        if d.get("breakglass"):
            waived.append({**item, "window": d["breakglass"]})
    seqs = [r.get("seq") for _, r in rows if isinstance(r.get("seq"), int)]
    return {"v": "verfy.today/1", "date": day.isoformat(), "total": sum(verdicts.values()), "verdicts": dict(verdicts),
            "agents": dict(agents.most_common()), "tools": dict(tools.most_common(5)), "blocked": blocked, "asked": asked,
            "would": would, "breakglass": waived, "control": control, "receipts": [min(seqs), max(seqs)] if seqs else None}


def text(s: dict[str, Any], verified: bool | None = None) -> str:
    when = datetime.fromisoformat(s["date"]).strftime("%d %B %Y").lstrip("0")
    lines = [f"Today, {when}"]
    if not s["total"] and not s["control"]:
        return lines[0] + ": no agent action was recorded on this computer."
    who = ", ".join(f"{a} ({n})" for a, n in s["agents"].items())
    lines.append(f"Your agents took {s['total']} action{'s' if s['total'] != 1 else ''} on this computer ({who}).")
    v = s["verdicts"]
    lines.append(f"{v.get('allow', 0)} ran without asking, {v.get('ask', 0)} needed a person and {v.get('deny', 0)} were blocked.")
    if s["tools"]:
        lines.append("Used most: " + ", ".join(f"{t} ({n})" for t, n in s["tools"].items()) + ".")
    if s["blocked"]:
        lines.append("")
        lines.append("Blocked:")
        lines += [f"  {b['time']}  {b['agent']}  {b['tool']}  ({', '.join(b['rules'][:3])})  receipt #{b['seq']}" for b in s["blocked"][:20]]
        if len(s["blocked"]) > 20:
            lines.append(f"  ... and {len(s['blocked']) - 20} more (verfy ledger show)")
    if s["asked"]:
        lines.append("")
        lines.append("Asked a person:")
        lines += [f"  {a['time']}  {a['agent']}  {a['tool']}  ({', '.join(a['rules'][:3])})" + (f"  approved by {a['approved_by']}" if a.get("approved_by") else "")
                  for a in s["asked"][:20]]
    if s["would"]:
        lines.append("")
        lines.append(f"Observe mode: {len(s['would'])} action(s) would have been blocked or asked about. Look at them before `verfy policy enforce`:")
        lines += [f"  {w['time']}  {w['tool']}  would {w['would']}  ({', '.join(w['rules'][:3])})" for w in s["would"][:20]]
    if s["breakglass"]:
        lines.append("")
        lines.append(f"Emergency access let {len(s['breakglass'])} action(s) through:")
        lines += [f"  {b['time']}  {b['tool']}  ({', '.join(b['rules'][:3])})  window {b['window']}" for b in s["breakglass"][:20]]
    if s["control"]:
        lines.append("")
        lines.append("Stops and emergency access: " + ", ".join(f"{c['what']} at {c['time']}" for c in s["control"]) + ".")
    if s["receipts"]:
        lines.append("")
        tail = "" if verified is None else ("; the receipt chain checks out." if verified else "; THE RECEIPT CHAIN DOES NOT CHECK OUT (verfy verify).")
        lines.append(f"Receipts #{s['receipts'][0]} to #{s['receipts'][1]}{tail}")
    return "\n".join(lines)
