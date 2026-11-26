"""Payment totals on this computer, for the limits that need them: ``payments.monthly_budget``, ``payments.merchants``
(per merchant, per day) and ``payments.categories`` (per category, per day and per month).

The MCP gateway adds a payment here once it went through, the way it counts the daily budget. Only amounts, payee
names and category names are kept (``spend.json`` in Verfy's folder), for the last 62 days.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ._util import PATTERNS
from .fileio import FileLock, atomic_write

FILE = "spend.json"
KEEP_DAYS = 62


def _keys(args: dict) -> tuple[str | None, str | None]:
    keys = {str(k).lower(): v for k, v in args.items()} if isinstance(args, dict) else {}
    payee = next((keys[k] for k in PATTERNS["recipient_keys"] if isinstance(keys.get(k), str)), None)
    cat = next((str(keys[k]) for k in PATTERNS["dlp"]["category_keys"] if isinstance(keys.get(k), (str, int)) and not isinstance(keys.get(k), bool)), None)
    return payee, cat


def _load(home: Path) -> dict:
    try:
        data = json.loads((home / FILE).read_text("utf-8"))
    except (OSError, ValueError):
        return {"days": {}}
    return data if isinstance(data, dict) and isinstance(data.get("days"), dict) else {"days": {}}


def context(home: Path, args: dict, now: datetime | None = None) -> dict[str, float]:
    """The totals precheck reads for one payment: today, this month, and for its payee and category."""
    now = now or datetime.now(timezone.utc)
    today, month = now.strftime("%Y-%m-%d"), now.strftime("%Y-%m")
    payee, cat = _keys(args)
    days = _load(home)["days"]
    out = {"spent_today": 0.0, "spent_month": 0.0, "spent_payee_today": 0.0, "spent_category_today": 0.0, "spent_category_month": 0.0}
    for day, d in days.items():
        if not isinstance(d, dict) or not day.startswith(month):
            continue
        out["spent_month"] += float(d.get("total") or 0)
        if cat is not None:
            out["spent_category_month"] += float((d.get("category") or {}).get(cat) or 0)
        if day == today:
            out["spent_today"] += float(d.get("total") or 0)
            if payee is not None:
                out["spent_payee_today"] += float((d.get("payee") or {}).get(payee) or 0)
            if cat is not None:
                out["spent_category_today"] += float((d.get("category") or {}).get(cat) or 0)
    return out


def add(home: Path, args: dict, amount: Any, now: datetime | None = None) -> None:
    """Count a payment that went through."""
    if isinstance(amount, bool) or not isinstance(amount, (int, float)) or amount <= 0:
        return
    now = now or datetime.now(timezone.utc)
    payee, cat = _keys(args)
    path = home / FILE
    home.mkdir(parents=True, exist_ok=True)
    with FileLock(path):
        data = _load(home)
        cutoff = (now - timedelta(days=KEEP_DAYS)).strftime("%Y-%m-%d")
        data["days"] = {k: v for k, v in data["days"].items() if k >= cutoff}
        d = data["days"].setdefault(now.strftime("%Y-%m-%d"), {"total": 0, "payee": {}, "category": {}})
        d["total"] = round(float(d.get("total") or 0) + amount, 6)
        if payee is not None:
            d.setdefault("payee", {})[payee] = round(float(d["payee"].get(payee) or 0) + amount, 6)
        if cat is not None:
            d.setdefault("category", {})[cat] = round(float(d["category"].get(cat) or 0) + amount, 6)
        atomic_write(path, json.dumps(data, indent=1) + "\n", durable=False)
