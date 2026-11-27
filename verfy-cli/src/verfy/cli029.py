"""Commands added in 0.29.0: stop and resume, emergency access, the daily summary, plain-language rules, rule packs,
observe mode, the policy simulator, time stamps, disclosure, evidence packs, exports, disputes, agent keys and
mandate checks. ``register`` adds them to the parser in cli.py."""

from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path


def _cli():
    from . import cli
    return cli


def _person(what: str) -> bool:
    """Only a person at a terminal opens or loosens these; an agent's hook is refused earlier (VFY-SELF-003)."""
    if sys.stdin.isatty() and sys.stdout.isatty():
        return True
    print(f"verfy: {what} needs a person at a terminal (run it yourself, not through an agent or a script).", file=sys.stderr)
    return False


def _user_policy_file() -> Path:
    return _cli().home_file("policy.json")


def _read_user_policy() -> dict:
    p = _user_policy_file()
    if p.exists() and p.read_text("utf-8").strip():
        data = json.loads(p.read_text("utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"{p} is not a JSON object")
        return data
    return {}


def _write_user_policy(data: dict) -> Path:
    from .fileio import atomic_write
    from .policy import load_policy
    load_policy(data)  # never write a policy that would not load
    p = _user_policy_file()
    p.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(p, json.dumps(data, indent=2) + "\n")
    team = _cli().home_file("team") / "policy.json"
    if team.exists():
        print(f"Note: your team's policy ({team}) is in force on this device, so this file applies when you leave the team.")
    return p


def _confirm(prompt: str, yes: bool) -> bool:
    if yes:
        return True
    if not sys.stdin.isatty():
        print("verfy: add --yes to write it without a question.", file=sys.stderr)
        return False
    return input(prompt + " [y/N] ").strip().lower() in ("y", "yes")


# ---------------------------------------------------------------- stop / resume / break glass

def cmd_stop(args) -> int:
    from . import control
    control.stop(_cli().verfy_home(), args.agent, args.reason or "")
    who = f"the agent `{args.agent}`" if args.agent else "every agent on this computer"
    print(f"Stopped {who}. Every action is blocked (VFY-STOP-001) until a person runs `verfy resume{' --agent ' + args.agent if args.agent else ''}`.")
    return 0


def cmd_resume(args) -> int:
    from . import control
    if not _person("verfy resume"):
        return 1
    left = control.resume(_cli().verfy_home(), args.agent)
    print("Running again." if not left else f"Resumed {args.agent}; still stopped: {', '.join((left.get('agents') or {}).keys()) or 'every agent'}.")
    return 0


def cmd_breakglass(args) -> int:
    from . import control
    home = _cli().verfy_home()
    if args.action == "status":
        st = control.state(home)
        bg = st["breakglass"]
        print(f"Emergency access open until {bg['until']} ({bg['id']}: {bg['reason']}; rules {', '.join(bg['rules'])})." if bg else "No emergency access is open.")
        if st["stop"]:
            print("Stopped: " + ("every agent" if st["stop"].get("all") else ", ".join((st["stop"].get("agents") or {}).keys())))
        return 0
    if args.action == "end":
        bg = control.close_breakglass(home)
        print(f"Closed emergency access {bg['id']}." if bg else "No emergency access was open.")
        return 0
    if not _person("verfy breakglass"):
        return 1
    if not args.reason:
        print("verfy breakglass: say why with --reason; it is recorded.", file=sys.stderr)
        return 2
    rules = args.rule or ["*"]
    print(f"Emergency access for {args.minutes} minute(s): " + ("every rule that asks is waived." if rules == ["*"] else "these rules are waived: " + ", ".join(rules) + "."))
    print("What guards Verfy, a stop and protected paths stay on. Every action in this time is recorded with this window's id.")
    if input("Type yes to open it: ").strip().lower() != "yes":
        print("Nothing opened.")
        return 1
    bg = control.open_breakglass(home, args.minutes, args.reason, rules)
    print(f"Open until {bg['until']} ({bg['id']}). `verfy breakglass end` closes it sooner.")
    return 0


def cmd_today(args) -> int:
    from . import daily
    from .receipts import read_ledger, verify_ledger
    path = _cli()._ledger_path(args)
    receipts = read_ledger(path) if path.exists() else []
    day = date.fromisoformat(args.date) if args.date else None
    s = daily.summarize(receipts, day)
    if args.json:
        print(json.dumps(s, indent=2))
        return 0
    verified = None
    if receipts and _cli().home_file("key.json").exists() and not args.ledger:
        verified = bool(verify_ledger(receipts, _cli().get_key(None).public).get("ok"))
    print(daily.text(s, verified))
    return 0


# ---------------------------------------------------------------- plain-language rules, packs, observe, simulate

def cmd_rule(args) -> int:
    from . import plainrules
    args.text = " ".join(args.text or [])
    if args.action == "list":
        pol = _read_user_policy()
        rules = pol.get("rules", [])
        if not rules and not pol.get("packs"):
            print("No rules of your own yet. Add one: verfy rule add \"ask before payments over 50\"")
        for r in rules:
            print(f"  {r.get('id', '?'):44} {r.get('verdict', 'ask'):5} {r.get('message', r.get('pattern', ''))}")
        if pol.get("packs"):
            print("Packs: " + ", ".join(pol["packs"]))
        return 0
    if args.action == "remove":
        new, hit = plainrules.remove_rule(_read_user_policy(), args.text)
        if not hit:
            print(f"verfy: no rule with the id {args.text!r} (verfy rule list)", file=sys.stderr)
            return 1
        print(f"Removed {args.text} from {_write_user_policy(new)}.")
        return 0
    try:
        r = plainrules.compile_rule(args.text)
    except plainrules.PlainRuleError as e:
        print(str(e), file=sys.stderr)
        return 2
    print(f"Rule:   {r['text']}")
    print(f"Does:   {r['says']}")
    print("Adds to your policy:")
    print("  " + json.dumps(r["patch"], indent=2).replace("\n", "\n  "))
    if args.action == "explain":
        return 0
    if not _confirm("Write this to your policy?", args.yes):
        print("Nothing written.")
        return 1
    print(f"Written to {_write_user_policy(plainrules.apply_patch(_read_user_policy(), r['patch']))}.")
    return 0


def cmd_pack(args) -> int:
    from . import plainrules
    if args.action == "list":
        mine = set(_read_user_policy().get("packs") or [])
        for name, p in plainrules.PACKS.items():
            print(f"  {'*' if name in mine else ' '} {name:10} {p['about']}")
        print("  (* = in your policy)  verfy policy pack add NAME")
        return 0
    if not args.name:
        print("verfy: name a pack (verfy policy pack list)", file=sys.stderr)
        return 2
    if args.action == "show":
        print(json.dumps(plainrules.pack_patch(args.name), indent=2))
        return 0
    pol = _read_user_policy()
    new = plainrules.add_pack(pol, args.name) if args.action == "add" else plainrules.remove_pack(pol, args.name)
    print(f"{'Added' if args.action == 'add' else 'Removed'} the {args.name} pack: {_write_user_policy(new)}.")
    return 0


def cmd_mode(args) -> int:
    observe = args.policy_cmd == "observe"
    if observe and not _person("verfy policy observe"):
        return 1
    pol = _read_user_policy()
    if observe:
        pol["mode"] = "observe"
    else:
        pol.pop("mode", None)
    p = _write_user_policy(pol)
    if observe:
        print(f"Observe mode ({p}): nothing is blocked; each receipt records what would have happened (decision.would).")
        print("What guards Verfy, a stop and protected paths stay on. `verfy today` lists what would have been blocked; `verfy policy enforce` ends it.")
    else:
        print(f"Enforcing again ({p}).")
    return 0


def cmd_simulate(args) -> int:
    from . import simulate
    from .policy import load_policy
    cli = _cli()
    current = cli.get_policy(argparse_ns(policy=None))
    new = cli._guard_home(load_policy(args.file))
    if args.source == "claude":
        actions = list(simulate.claude_actions(days=args.days))
        where = f"Claude Code's transcripts from the last {args.days} day(s)"
    else:
        actions = simulate.file_actions(Path(args.source))
        where = args.source
    res = simulate.simulate(actions, current, new)
    if args.json:
        print(json.dumps(res, indent=2))
        return 0
    b, a = res["before"], res["after"]
    print(f"{res['total']} actions from {where}")
    print(f"  now:      {b.get('allow', 0)} allowed, {b.get('ask', 0)} asked, {b.get('deny', 0)} blocked")
    print(f"  with it:  {a.get('allow', 0)} allowed, {a.get('ask', 0)} asked, {a.get('deny', 0)} blocked")
    if not res["changed"]:
        print("No action would get a different answer.")
    for ch in res["changed"][:args.limit]:
        print(f"  {ch['before']:5} -> {ch['after']:5}  {ch['tool']}  {ch['summary']}  ({', '.join(ch['rules'][:3])})")
    if len(res["changed"]) > args.limit:
        print(f"  ... and {len(res['changed']) - args.limit} more (--json for all)")
    return 0


def argparse_ns(**kw):
    import argparse
    return argparse.Namespace(**kw)


# ---------------------------------------------------------------- time stamps, disclosure, evidence, export, disputes

def cmd_timestamp(args) -> int:
    from . import tsa
    from .receipts import read_ledger, receipt_hash
    cli = _cli()
    if args.action == "verify":
        receipts = read_ledger(cli._ledger_path(args)) if cli._ledger_path(args).exists() else None
        out = tsa.check_file(Path(args.file), receipts, Path(args.ca) if args.ca else None)
        print(f"Stamped hash  {out['head']}")
        print(f"Time          {out['gen_time']}  (serial {out['serial']})")
        if receipts is not None:
            print(f"Ledger        {'receipt #' + str(out['seq']) + ' (and every receipt before it)' if out['seq'] is not None else 'NOT a receipt in this ledger'}")
        sig = {"ok": "checked with OpenSSL: OK", "bad": "checked with OpenSSL: FAILED", "not checked": "not checked here; run:"}[out["signature"]]
        print(f"Signature     {sig}" + (f"\n  {out['command']} -CAfile <the authority's CA certificates>" if out["signature"] == "not checked" else ""))
        return 0 if out["signature"] != "bad" and (receipts is None or out["seq"] is not None) else 1
    if args.action == "list":
        d = cli.verfy_home() / "timestamps"
        for f in sorted(d.glob("*.json")) if d.exists() else []:
            m = json.loads(f.read_text("utf-8"))
            print(f"  #{m.get('seq')}  {m.get('gen_time')}  {m.get('tsa')}  {f.with_suffix('.tsr').name}")
        return 0
    receipts = read_ledger(cli._ledger_path(args))
    if not receipts:
        print("verfy: the ledger is empty; nothing to stamp yet.", file=sys.stderr)
        return 1
    head = receipt_hash(receipts[-1])
    info = tsa.stamp(head, args.tsa)
    path = tsa.save(cli.verfy_home(), info, receipts[-1].get("seq"))
    print(f"Stamped receipt #{receipts[-1].get('seq')} ({head}) at {info['gen_time']} by {args.tsa}.")
    print(f"Saved {path}. Check it: verfy timestamp verify {path}")
    return 0


def cmd_disclose(args) -> int:
    from . import disclose
    from .receipts import public_from, read_ledger
    cli = _cli()
    if args.action == "verify":
        doc = json.loads(Path(args.file).read_text("utf-8"))
        res = disclose.verify_disclosure(doc, public_from(args.pub))
        print(("VERIFIED" if res["ok"] else "FAILED") + f"  receipt #{res['receipt'].get('seq')} {res['receipt'].get('tool')} ({res['receipt'].get('verdict')}), {res['receipt'].get('issued_at')}")
        for k, v in res["shown"].items():
            print(f"  shown   {k} = {json.dumps(v)}")
        for k in res["hidden"]:
            print(f"  hidden  {k}")
        for p in res["problems"]:
            print(f"  problem {p}")
        return 0 if res["ok"] else 1
    receipts = read_ledger(cli._ledger_path(args))
    target = next((r for r in receipts if r.get("seq") == args.seq), None)
    if target is None:
        print(f"verfy: no receipt #{args.seq}", file=sys.stderr)
        return 1
    key = cli.get_key(None)
    doc = disclose.disclose(target, json.loads(Path(args.args).read_text("utf-8")), [s.strip() for s in args.show.split(",") if s.strip()], key.hash_salt())
    text = json.dumps(doc, indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(text, "utf-8")
        print(f"Wrote {args.out}. The reader checks it with: verfy disclose verify {args.out} --pub {key.to_json(False)['public']}")
    else:
        print(text, end="")
    return 0


def cmd_evidence(args) -> int:
    from . import __version__, evidence
    from .receipts import read_ledger, verify_ledger
    cli = _cli()
    path = cli._ledger_path(args)
    receipts = read_ledger(path)
    key = cli.get_key(None)
    ver = verify_ledger(receipts, key.public)
    data = evidence.build(receipts, ver, kid=key.kid, public=key.to_json(False)["public"], policy=cli.get_policy(argparse_ns(policy=None)),
                          frameworks=evidence.names(args.framework), version=__version__, ledger_text=path.read_text("utf-8"),
                          since=args.since, until=args.until)
    out = Path(args.out or f"verfy-evidence-{date.today().isoformat()}.zip")
    out.write_bytes(data)
    print(f"Wrote {out} ({len(receipts)} receipts, chain {'intact' if ver.get('ok') else 'BROKEN'}): summary, controls, report.html, report.pdf, the ledger and how to check it.")
    return 0 if ver.get("ok") else 1


def cmd_export(args) -> int:
    from . import __version__, export
    from .receipts import public_from, read_ledger
    cli = _cli()
    if args.action == "verify":
        text = Path(args.file).read_text("utf-8")
        pub = public_from(args.pub)
        if args.format == "acta":
            items = json.loads(text) if text.lstrip().startswith("[") else [json.loads(x) for x in text.splitlines() if x.strip()]
            res = export.verify_acta(items, pub)
        elif args.format == "aar":
            res = export.verify_aar([x for x in text.splitlines() if x.strip()], pub.hex())
        else:
            print("verfy: OCSF events are not signed; check the ledger they came from with verfy verify.", file=sys.stderr)
            return 2
        print(("VERIFIED" if res["ok"] else "FAILED") + f"  {res['count']} receipts ({res['draft']})")
        for e in res["errors"][:20]:
            print("  " + e)
        return 0 if res["ok"] else 1
    receipts = read_ledger(cli._ledger_path(args))
    if args.format == "ocsf":
        lines = [json.dumps(e, separators=(",", ":")) for e in export.ocsf(receipts, __version__)]
    elif args.format == "acta":
        lines = [json.dumps(e, separators=(",", ":"), ensure_ascii=False) for e in export.acta(receipts, cli.get_key(None))]
    else:
        lines = export.aar(receipts, cli.get_key(None))
    text = "\n".join(lines) + ("\n" if lines else "")
    if args.out:
        Path(args.out).write_text(text, "utf-8")
        print(f"Wrote {len(lines)} {args.format} records to {args.out}.", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


def cmd_dispute(args) -> int:
    from . import dispute
    from .receipts import read_ledger
    cli = _cli()
    if args.action in ("verify", "send"):
        if not args.file:
            print(f"usage: verfy dispute {args.action} FILE", file=sys.stderr)
            return 2
        doc = json.loads(Path(args.file).read_text("utf-8"))
        res = dispute.verify_dispute(doc)
        print(("VERIFIED" if res["ok"] else "FAILED") + f"  finding: {res.get('finding')}")
        for p in res["problems"]:
            print("  " + p)
        if args.action == "verify" or not res["ok"]:
            return 0 if res["ok"] else 1
        from . import team
        try:
            sent = team.send_dispute(cli.verfy_home(), doc)
        except team.TeamError as e:
            print(f"verfy: {e}", file=sys.stderr)
            return 1
        enrolled = "an enrolled device of your team" if sent.get("signer_enrolled") else "a key that is not an enrolled device of your team"
        print(f"Sent to Verfy Cloud ({sent.get('id')}); signed by {enrolled}.")
        print("An owner or admin names the person who decides under Disputes. Verfy does not judge.")
        return 0
    doc = dispute.open_dispute(read_ledger(cli._ledger_path(args)), args.seq, args.claim or "", cli.get_key(None), args.by or "")
    out = Path(args.out or f"{doc['id']}.json")
    out.write_text(json.dumps(doc, indent=2) + "\n", "utf-8")
    print(f"Finding: {dispute.FINDINGS[doc['finding']]}")
    for f in doc["facts"][1:]:
        print(f"  {f}")
    print(f"Wrote {out}. Anyone can check it: verfy dispute verify {out}")
    print("This finding comes from fixed rules; a person decides who is responsible.")
    return 0


# ---------------------------------------------------------------- agent keys, mandates

def cmd_agent(args) -> int:
    from . import identity
    from .receipts import Key, public_from, read_ledger
    cli = _cli()
    d = cli.verfy_home() / "agents"
    if args.action == "list":
        for cert_file in sorted(d.glob("*/cert.json")) if d.exists() else []:
            cert = json.loads(cert_file.read_text("utf-8"))
            revoked = (cert_file.parent / "revoked.json").exists()
            print(f"  {cert['agent']:24} {cert['agent_kid']}  until {cert['expires_at']}{'  REVOKED' if revoked else ''}")
        return 0
    if args.action == "verify":
        cert = json.loads(Path(args.name).read_text("utf-8"))
        owner = public_from(args.owner)
        revs = [json.loads(Path(f).read_text("utf-8")) for f in args.revocation or []]
        if args.ledger:
            res = identity.verify_agent_ledger(read_ledger(Path(args.ledger)), cert, owner, revs)
        else:
            res = identity.verify_cert(cert, owner, revs)
        print(("VERIFIED" if res["ok"] else "FAILED") + f"  agent {res.get('agent')} belongs to {cert.get('owner_kid')}")
        for p in res["problems"]:
            print("  " + p)
        return 0 if res["ok"] else 1
    owner = cli.get_key(None)
    folder = d / args.name
    if args.action == "revoke":
        cert = json.loads((folder / "cert.json").read_text("utf-8"))
        identity.save_json(folder / "revoked.json", identity.revoke(owner, cert, args.reason or ""))
        print(f"Revoked {args.name}. Hand {folder / 'revoked.json'} to whoever checks its receipts.")
        return 0
    if not _person("verfy agent create"):
        return 1
    if (folder / "key.json").exists():
        print(f"verfy: {folder} already has a key.", file=sys.stderr)
        return 1
    agent, cert = identity.create_agent(owner, args.name, args.days)
    folder.mkdir(parents=True, exist_ok=True)
    agent.save(folder / "key.json")
    identity.save_json(folder / "cert.json", cert)
    print(f"Agent key {agent.kid} for {args.name}, certified by your key {owner.kid} until {cert['expires_at']}.")
    print(f"  key   {folder / 'key.json'}  (Recorder(key=...) signs with it; keep it private)")
    print(f"  cert  {folder / 'cert.json'}  (share it; verfy agent verify {folder / 'cert.json'} --owner {owner.to_json(False)['public']})")
    return 0


def cmd_mandate(args) -> int:
    from . import mandate
    m = json.loads(Path(args.file).read_text("utf-8"))
    res = mandate.check(m, amount=args.amount, currency=args.currency, payee=args.payee)
    print(f"{res['verdict'].upper()}  ({res['kind']})")
    for f in res["findings"]:
        print(f"  [{f['rule']}] {f['message']}")
    return {"allow": 0, "ask": 1, "deny": 2}[res["verdict"]]


# ---------------------------------------------------------------- parser

def register(sub, pol) -> None:
    from .tsa import DEFAULT_TSA
    x = pol.add_parser("observe", help="record what the rules would do, block nothing (what guards Verfy stays on)")
    x.set_defaults(fn=cmd_mode)
    x = pol.add_parser("enforce", help="end observe mode")
    x.set_defaults(fn=cmd_mode)
    x = pol.add_parser("simulate", help="try a policy on actions agents already took, before turning it on")
    x.add_argument("file", help="the policy JSON to try")
    x.add_argument("--from", dest="source", default="claude", help="claude (Claude Code transcripts here, default) or a JSON/JSONL file of actions")
    x.add_argument("--days", type=int, default=7)
    x.add_argument("--limit", type=int, default=30)
    x.add_argument("--json", action="store_true")
    x.set_defaults(fn=cmd_simulate)
    x = pol.add_parser("pack", help="ready rule packs: github, databases, slack, payments, email, cloud")
    x.add_argument("action", choices=["list", "show", "add", "remove"])
    x.add_argument("name", nargs="?")
    x.set_defaults(fn=cmd_pack)

    p = sub.add_parser("stop", help="block every action of every agent here (or of one, --agent) until a person runs verfy resume")
    p.add_argument("--agent", help="only this agent: claude-code, cursor, codex, gemini, copilot, windsurf, devin, or mcp:<server>")
    p.add_argument("--reason")
    p.set_defaults(fn=cmd_stop)
    p = sub.add_parser("resume", help="start the agents again after verfy stop (a person, at a terminal)")
    p.add_argument("--agent")
    p.set_defaults(fn=cmd_resume)
    p = sub.add_parser("breakglass", help="emergency access: waive rules for a few minutes, every action marked in its receipt")
    p.add_argument("action", nargs="?", choices=["open", "end", "status"], default="open")
    p.add_argument("--minutes", type=int, default=30)
    p.add_argument("--reason")
    p.add_argument("--rule", action="append", help="waive only this rule (or VFY-XX-* pattern); repeat for more; default: every rule that asks")
    p.set_defaults(fn=cmd_breakglass)
    p = sub.add_parser("today", help="what your agents did today, in plain words, from the receipts")
    p.add_argument("--date", help="another day, YYYY-MM-DD")
    p.add_argument("--ledger")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_today)
    p = sub.add_parser("rule", help='rules in plain English: verfy rule add "ask before payments over 50"')
    p.add_argument("action", choices=["add", "explain", "list", "remove"])
    p.add_argument("text", nargs="*", help="the rule as a sentence (add, explain) or its id (remove); quotes are optional")
    p.add_argument("--yes", action="store_true", help="write without asking")
    p.set_defaults(fn=cmd_rule)
    p = sub.add_parser("timestamp", help="have a time stamp authority (RFC 3161) sign the ledger head")
    p.add_argument("action", nargs="?", choices=["stamp", "verify", "list"], default="stamp")
    p.add_argument("file", nargs="?")
    p.add_argument("--tsa", default=DEFAULT_TSA)
    p.add_argument("--ca", help="the authority's CA certificates, to check its signature with OpenSSL")
    p.add_argument("--ledger")
    p.set_defaults(fn=cmd_timestamp)
    p = sub.add_parser("disclose", help="show chosen arguments of a receipt and keep the rest hidden")
    p.add_argument("action", nargs="?", choices=["make", "verify"], default="make")
    p.add_argument("file", nargs="?", help="verify: the disclosure file")
    p.add_argument("--seq", type=int)
    p.add_argument("--args", help="a JSON file with the arguments the agent used")
    p.add_argument("--show", default="", help="argument names to show, comma-separated")
    p.add_argument("--pub")
    p.add_argument("--out")
    p.add_argument("--ledger")
    p.set_defaults(fn=cmd_disclose)
    p = sub.add_parser("evidence", help="a zip for an auditor: receipts mapped to SOC 2, ISO/IEC 42001, AIUC-1 and EU AI Act controls")
    p.add_argument("--framework", default="all", help="all, or a comma list of soc2, iso42001, aiuc1, eu-ai-act")
    p.add_argument("--since")
    p.add_argument("--until")
    p.add_argument("--out")
    p.add_argument("--ledger")
    p.set_defaults(fn=cmd_evidence)
    p = sub.add_parser("export", help="the ledger as OCSF events (SIEM) or as IETF-draft receipts (acta, aar)")
    p.add_argument("action", nargs="?", choices=["write", "verify"], default="write")
    p.add_argument("file", nargs="?")
    p.add_argument("--format", choices=["ocsf", "acta", "aar"], required=True)
    p.add_argument("--pub")
    p.add_argument("--out")
    p.add_argument("--ledger")
    p.set_defaults(fn=cmd_export)
    p = sub.add_parser("dispute", help="a signed dispute record from a receipt, with a first finding by fixed rules; send puts it in Verfy Cloud")
    p.add_argument("action", choices=["open", "verify", "send"])
    p.add_argument("file", nargs="?")
    p.add_argument("--seq", type=int)
    p.add_argument("--claim")
    p.add_argument("--by")
    p.add_argument("--out")
    p.add_argument("--ledger")
    p.set_defaults(fn=cmd_dispute)
    p = sub.add_parser("agent", help="keys for each agent, certified by your key, so receipts show whose agent acted")
    p.add_argument("action", choices=["create", "list", "revoke", "verify"])
    p.add_argument("name", nargs="?", help="the agent's name (verify: the cert.json file)")
    p.add_argument("--days", type=int, default=365)
    p.add_argument("--reason")
    p.add_argument("--owner", help="verify: the owner's public key")
    p.add_argument("--ledger", help="verify: the agent's ledger too")
    p.add_argument("--revocation", action="append")
    p.set_defaults(fn=cmd_agent)
    p = sub.add_parser("mandate", help="check a payment against an AP2 mandate or x402 payment requirements")
    p.add_argument("action", choices=["check"])
    p.add_argument("file")
    p.add_argument("--amount", required=True)
    p.add_argument("--currency")
    p.add_argument("--payee")
    p.set_defaults(fn=cmd_mandate)
