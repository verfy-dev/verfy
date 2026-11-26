"""Verfy: security, policy and verifiable evidence for coding agents and MCP tools.

Guard every tool call with deterministic rules, scan and lock MCP tool
definitions, and sign a tamper-evident receipt for everything that happened.
Any program can sign receipts for its own actions too: ``verfy.record()``,
``@verfy.track(...)`` and ``verfy.Recorder``.
"""


__version__ = "0.28.1"

# `canonical` is also the name of a submodule: bound here, or importing the submodule would put the module in its place
from .canonical import canonical, digest  # noqa: E402

# loaded when first used, so the hook (entry.py -> hookenv.py) does not pay for the recorder and the scanner
_LAZY = {"DEFAULT_POLICY": "policy", "load_policy": "policy", "policy_digest": "policy",
         "check": "precheck", "classify": "precheck", "ActionDenied": "recorder", "Recorder": "recorder", "RecordError": "recorder",
         "record": "recorder", "track": "recorder", "scan": "scanner", "tool_pin": "scanner"}


def __getattr__(name: str):
    if name in _LAZY:
        import importlib
        value = getattr(importlib.import_module(f".{_LAZY[name]}", __name__), name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted([*globals(), *_LAZY])


__all__ = ["canonical", "digest", "DEFAULT_POLICY", "load_policy", "policy_digest", "check", "classify", "scan", "tool_pin",
           "Recorder", "RecordError", "ActionDenied", "record", "track", "__version__"]
