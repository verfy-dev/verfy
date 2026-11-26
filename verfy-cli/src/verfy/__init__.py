"""Verfy: security, policy and verifiable evidence for coding agents and MCP tools.

Guard every tool call with deterministic rules, scan and lock MCP tool
definitions, and sign a tamper-evident receipt for everything that happened.
Any program can sign receipts for its own actions too: ``verfy.record()``,
``@verfy.track(...)`` and ``verfy.Recorder``.
"""

from .canonical import canonical, digest
from .policy import DEFAULT_POLICY, load_policy, policy_digest
from .precheck import check, classify
from .recorder import ActionDenied, Recorder, RecordError, record, track
from .scanner import scan, tool_pin

__version__ = "0.28.0"

__all__ = ["canonical", "digest", "DEFAULT_POLICY", "load_policy", "policy_digest", "check", "classify", "scan", "tool_pin",
           "Recorder", "RecordError", "ActionDenied", "record", "track", "__version__"]
