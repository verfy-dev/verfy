"""Verfy receipts for agent frameworks, with nothing to change in the tools themselves.

- ``verfy.integrations.langchain.VerfyCallbackHandler``: a LangChain callback handler (LangChain, LangGraph).
- ``verfy.integrations.openai_agents.VerfyRunHooks``: run hooks for the OpenAI Agents SDK.

Each records every tool call as a signed receipt through a ``verfy.Recorder`` and, when the recorder has rules
(``Recorder(rules=[...])`` or the team's policy), checks them before the tool runs: a call they stop raises
``verfy.ActionDenied`` and the tool does not run. The frameworks themselves are not dependencies of Verfy; each module
imports its framework only when it is installed.
"""

from __future__ import annotations

from typing import Any

from ..recorder import ActionDenied, Recorder, _error_value, _safe_write, default_recorder, jsonable

__all__ = ["ToolCalls"]


class ToolCalls:
    """What both integrations share: open calls by id, guarding, and writing the receipt when a call ends."""

    def __init__(self, recorder: Recorder | None, *, system: str, kinds: dict[str, str] | None, kind: str, guard: bool | None,
                 record_result: bool):
        import threading
        self.recorder = recorder
        self.system = system
        self.kinds = dict(kinds or {})
        self.kind = kind
        self.guard = guard
        self.record_result = record_result
        self._open: dict[Any, tuple[str, Any, dict | None]] = {}
        self._stopped: set[Any] = set()
        self._lock = threading.Lock()

    @property
    def rec(self) -> Recorder:
        return self.recorder or default_recorder()

    def kind_of(self, name: str) -> str:
        return self.kinds.get(name, self.kind)

    def start(self, call_id: Any, name: str, args: Any) -> None:
        """Check the rules (raising ActionDenied, which the framework passes up) and remember the call."""
        rec = self.rec
        args = jsonable(args if args is not None else {}, strict=False)
        decision = None
        if (bool(rec.rules) if self.guard is None else self.guard):
            try:
                decision = rec._guard(name, system=self.system, kind=self.kind_of(name), args=args, session=None)
            except ActionDenied:
                with self._lock:
                    self._stopped.add(call_id)
                raise
        with self._lock:
            self._open[call_id] = (name, args, decision)

    def end(self, call_id: Any, name: str | None, ok: bool, value: Any) -> dict | None:
        with self._lock:
            if call_id in self._stopped:  # already recorded as blocked or declined
                self._stopped.discard(call_id)
                return None
            opened = self._open.pop(call_id, None)
        tool, args, decision = opened if opened else (name or "tool", {}, None)
        if ok:
            result = jsonable(value, strict=False) if self.record_result and value is not None else None
            return _safe_write(self.rec, tool, system=self.system, kind=self.kind_of(tool), args=args, status="ok", result=result,
                               session=None, decision=decision)
        return _safe_write(self.rec, tool, system=self.system, kind=self.kind_of(tool), args=args, status="error",
                           result=_error_value(value) if isinstance(value, BaseException) else {"error": str(value)[:2000]},
                           session=None, raising=False, decision=decision)
