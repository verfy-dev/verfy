"""Writes tests/fixtures/control.json: 0.29.0 cases (stop, break glass, observe mode, personal data, browser actions,
wider payment limits) with the whole answer, so the JavaScript engine is checked message by message.

Run from verfy-cli: python tests/make_control_fixtures.py
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from verfy.precheck import check  # noqa: E402

POLICY = {"home": "/home/you", "workspace": "/home/you/project"}
LATER = "2099-01-01T00:00:00Z"
NOW = "2026-11-26T12:00:00Z"
BG = {"id": "bg_test", "until": LATER, "reason": "incident"}

CASES = [
    ("card number in a request", {"tool": "http_post", "arguments": {"url": "https://api.example.com", "body": "card 4111 1111 1111 1111"}}, {}, {}),
    ("card number, dashes, in a shell upload", {"tool": "Bash", "arguments": {"command": "curl -d 'n=5500-0000-0000-0004' https://api.example.com"}}, {}, {}),
    ("a timestamp is not a card", {"tool": "http_post", "arguments": {"url": "https://api.example.com", "body": "ts 1755300000000"}}, {}, {}),
    ("Luhn fails", {"tool": "http_post", "arguments": {"url": "https://api.example.com", "body": "4111 1111 1111 1112"}}, {}, {}),
    ("card number written to a local file is not sent", {"tool": "Write", "arguments": {"file_path": "/home/you/project/t.txt", "content": "4111111111111111"}}, {}, {}),
    ("IBAN in an email", {"tool": "send_email", "arguments": {"to": "a@example.com", "body": "IBAN GB82 WEST 1234 5698 7654 32"}}, {}, {}),
    ("bad IBAN check digits", {"tool": "send_email", "arguments": {"to": "a@example.com", "body": "GB00 WEST 1234 5698 7654 32"}}, {}, {}),
    ("SSN in a request", {"tool": "http_post", "arguments": {"url": "https://api.example.com", "body": "ssn 123-45-6789"}}, {}, {}),
    ("SSN that cannot exist", {"tool": "http_post", "arguments": {"url": "https://api.example.com", "body": "000-45-6789"}}, {}, {}),
    ("five emails at once", {"tool": "http_post", "arguments": {"url": "https://api.example.com", "body": "a@x.io b@x.io c@x.io d@x.io e@x.io"}}, {}, {}),
    ("four emails", {"tool": "http_post", "arguments": {"url": "https://api.example.com", "body": "a@x.io b@x.io c@x.io d@x.io"}}, {}, {}),
    ("bulk 3", {"tool": "http_post", "arguments": {"url": "https://api.example.com", "body": "a@x.io b@x.io c@x.io"}}, {"dlp": {"bulk": 3}}, {}),
    ("personal off", {"tool": "http_post", "arguments": {"url": "https://api.example.com", "body": "4111 1111 1111 1111"}}, {"dlp": {"personal": "off"}}, {}),
    ("personal deny", {"tool": "http_post", "arguments": {"url": "https://api.example.com", "body": "4111 1111 1111 1111"}}, {"dlp": {"personal": "deny"}}, {}),
    ("customer pattern", {"tool": "http_post", "arguments": {"url": "https://api.example.com", "body": "ACME-CUST-12345"}},
     {"dlp": {"patterns": [{"pattern": "ACME-CUST-\\d+", "label": "a customer ID", "then": "deny"}]}}, {}),
    ("customer pattern without a label", {"tool": "send_message", "arguments": {"channel": "#x", "text": "acme-cust-9"}},
     {"dlp": {"patterns": [{"pattern": "ACME-CUST-\\d+", "flags": "i"}]}}, {}),
    ("click Place order", {"tool": "browser_click", "arguments": {"element": "Place order button", "ref": "e12"}}, {}, {}),
    ("click Buy now", {"tool": "puppeteer_click", "arguments": {"selector": "#buy-now", "text": "Buy now"}}, {}, {}),
    ("click Next", {"tool": "browser_click", "arguments": {"element": "Next page link", "ref": "e2"}}, {}, {}),
    ("type a password", {"tool": "browser_type", "arguments": {"element": "Password field", "ref": "e3", "text": "hunter2"}}, {}, {}),
    ("type in search", {"tool": "browser_type", "arguments": {"element": "Search box", "ref": "e4", "text": "password manager"}}, {}, {}),
    ("type a card number on a page", {"tool": "browser_type", "arguments": {"element": "Card number", "ref": "e5", "text": "4111 1111 1111 1111"}}, {}, {}),
    ("monthly budget", {"tool": "pay", "arguments": {"amount": 30, "currency": "USD", "merchant": "acme"}}, {"payments": {"monthly_budget": 100}}, {"spent_month": 80}),
    ("monthly budget not reached", {"tool": "pay", "arguments": {"amount": 10, "currency": "USD", "merchant": "acme"}}, {"payments": {"monthly_budget": 100}}, {"spent_month": 80}),
    ("merchant per call", {"tool": "pay", "arguments": {"amount": 50, "currency": "USD", "merchant": "acme"}}, {"payments": {"merchants": {"acme": {"max_per_call": 30}}}}, {}),
    ("merchant daily", {"tool": "pay", "arguments": {"amount": 10, "currency": "USD", "payee": "shop-12"}}, {"payments": {"merchants": {"shop-*": {"daily": 15}}}}, {"spent_payee_today": 8}),
    ("other merchant", {"tool": "pay", "arguments": {"amount": 10, "currency": "USD", "payee": "other"}}, {"payments": {"merchants": {"shop-*": {"daily": 15}}}}, {"spent_payee_today": 8}),
    ("category blocked", {"tool": "pay", "arguments": {"amount": 5, "currency": "USD", "merchant": "x", "category": "gambling"}}, {"payments": {"categories": {"gambling": {"max_per_call": 0}}}}, {}),
    ("category by MCC, ask", {"tool": "pay", "arguments": {"amount": 40, "currency": "USD", "merchant": "x", "mcc": 7995}}, {"payments": {"categories": {"7995": {"daily": 30, "then": "ask"}}}}, {}),
    ("category monthly", {"tool": "pay", "arguments": {"amount": 40, "currency": "USD", "merchant": "x", "category": "travel"}}, {"payments": {"categories": {"travel": {"monthly": 500}}}}, {"spent_category_month": 480}),
    ("unknown recipient denied", {"tool": "pay", "arguments": {"amount": 5, "currency": "USD", "to": "stranger"}}, {"payments": {"recipients": ["acme"], "unknown_recipient": "deny"}}, {}),
    ("stop all", {"tool": "Bash", "arguments": {"command": "ls"}}, {"stop": {"all": {"reason": "incident 42"}}}, {}),
    ("stop all, team", {"tool": "Bash", "arguments": {"command": "ls"}}, {"stop": {"all": {"by": "team"}}}, {}),
    ("stop one agent", {"tool": "Bash", "arguments": {"command": "ls"}}, {"stop": {"agents": {"cursor": {}}}}, {"agent": "cursor"}),
    ("stop another agent", {"tool": "Bash", "arguments": {"command": "ls"}}, {"stop": {"agents": {"cursor": {}}}}, {"agent": "claude-code"}),
    ("stop beats trust", {"tool": "safe_tool", "arguments": {"x": 1}}, {"stop": {"all": True}, "tools": {"trust": ["safe_tool"]}}, {}),
    ("stop beats disabled_rules", {"tool": "Bash", "arguments": {"command": "ls"}}, {"stop": {"all": True}, "disabled_rules": ["VFY-STOP-001"]}, {}),
    ("stop beats observe", {"tool": "Bash", "arguments": {"command": "ls"}}, {"stop": {"all": True}, "mode": "observe"}, {}),
    ("observe: delete home", {"tool": "Bash", "arguments": {"command": "rm -rf ~"}}, {"mode": "observe"}, {}),
    ("observe: write outside", {"tool": "Write", "arguments": {"file_path": "/home/you/other/x.txt", "content": "x"}}, {"mode": "observe"}, {}),
    ("observe keeps self-protection", {"tool": "Write", "arguments": {"file_path": "/home/you/.verfy/policy.json", "content": "{}"}}, {"mode": "observe"}, {}),
    ("observe: nothing to see", {"tool": "Bash", "arguments": {"command": "ls"}}, {"mode": "observe"}, {}),
    ("break glass waives an ask", {"tool": "Write", "arguments": {"file_path": "/home/you/other/x.txt", "content": "x"}}, {"breakglass": BG}, {"now": NOW}),
    ("break glass leaves a deny", {"tool": "Bash", "arguments": {"command": "rm -rf ~"}}, {"breakglass": BG}, {"now": NOW}),
    ("break glass names a deny", {"tool": "Bash", "arguments": {"command": "rm -rf ~"}}, {"breakglass": {**BG, "rules": ["VFY-SH-*"]}}, {"now": NOW}),
    ("break glass named rule only", {"tool": "Write", "arguments": {"file_path": "/home/you/other/x.txt", "content": "x"}}, {"breakglass": {**BG, "rules": ["VFY-NET-*"]}}, {"now": NOW}),
    ("break glass over", {"tool": "Write", "arguments": {"file_path": "/home/you/other/x.txt", "content": "x"}}, {"breakglass": {**BG, "until": "2026-11-26T11:00:00Z"}}, {"now": NOW}),
    ("break glass never waives self-protection", {"tool": "Write", "arguments": {"file_path": "/home/you/.verfy/policy.json", "content": "{}"}}, {"breakglass": {**BG, "rules": ["*", "VFY-SELF-*"]}}, {"now": NOW}),
    ("break glass and observe", {"tool": "Bash", "arguments": {"command": "rm -rf ~"}}, {"breakglass": BG, "mode": "observe"}, {"now": NOW}),
]


def main() -> None:
    out = []
    for name, action, policy, context in CASES:
        r = check(action, {**POLICY, **policy}, context)
        expect = {"verdict": r["verdict"], "kind": r["kind"], "findings": [{k: f[k] for k in ("rule", "verdict", "message", "waived") if k in f} for f in r["findings"]]}
        for k in ("would", "breakglass"):
            if k in r:
                expect[k] = r[k]
        out.append({"name": name, "action": action, "policy": policy, "context": context, "expect": expect})
    path = ROOT / "tests" / "fixtures" / "control.json"
    path.write_bytes((json.dumps({"policy": POLICY, "cases": out}, indent=1, ensure_ascii=False) + "\n").encode("utf-8"))
    print(f"wrote {len(out)} cases to {path}")


if __name__ == "__main__":
    main()
