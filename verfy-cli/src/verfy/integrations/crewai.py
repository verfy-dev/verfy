"""Verfy receipts for CrewAI tool calls (CrewAI 1.x tool-call hooks).

::

    from verfy import Recorder
    from verfy.integrations.crewai import VerfyCrewHooks

    VerfyCrewHooks(Recorder("research-crew", rules=[...]), kinds={"refund": "payment"}).register()
    crew.kickoff()

or only around one run: ``with VerfyCrewHooks(rec): crew.kickoff()``.

Every tool call any agent of any crew makes becomes a signed receipt: the tool's name, its input (hashed, unless the
recorder stores arguments) and "ok" with the hash of its output, or "error". With rules, a call they stop does not
run: the hook answers CrewAI's "block", and the agent reads Verfy's reason instead of a result.

CrewAI logs and ignores an exception raised in a hook and then runs the tool, so this hook never raises: anything that
goes wrong while checking a call blocks that call (it fails closed).
"""

from __future__ import annotations

import threading
from typing import Any

from . import ToolCalls
from ..recorder import ActionDenied, Recorder

__all__ = ["VerfyCrewHooks"]

BLOCKED_PREFIX = "Tool execution blocked by hook."


def _hooks():
    try:
        from crewai import hooks
    except ImportError:  # pragma: no cover - depends on what is installed
        raise ImportError("CrewAI is not installed: pip install crewai (1.0 or later)") from None
    return hooks


class VerfyCrewHooks:
    """Before and after hooks for CrewAI tool calls that record each call and check the recorder's rules first."""

    def __init__(self, recorder: Recorder | None = None, *, system: str = "crewai", kinds: dict[str, str] | None = None,
                 kind: str = "other", guard: bool | None = None, record_result: bool = True):
        self.calls = ToolCalls(recorder, system=system, kinds=kinds, kind=kind, guard=guard, record_result=record_result)
        self._reasons: dict[int, str] = {}
        self._lock = threading.Lock()

    # CrewAI passes the same input dict to the before and the after hook of one call, a new context object to each
    @staticmethod
    def _key(context: Any) -> int:
        return id(getattr(context, "tool_input", None))

    def before(self, context: Any) -> bool | None:
        key = self._key(context)
        name = str(getattr(context, "tool_name", "") or "tool")
        data = getattr(context, "tool_input", None)
        try:
            self.calls.start(key, name, dict(data) if isinstance(data, dict) else {"input": data})
        except ActionDenied as e:
            with self._lock:
                self._reasons[key] = str(e)
            return False
        except Exception as e:  # noqa: BLE001 - CrewAI would ignore it and run the tool
            self.calls.drop(key)
            with self._lock:
                self._reasons[key] = f"Verfy could not check this call ({type(e).__name__}: {str(e)[:200]}), so it did not run."
            return False
        return None

    def after(self, context: Any) -> str | None:
        key = self._key(context)
        with self._lock:
            reason = self._reasons.pop(key, None)
        if reason is not None:
            self.calls.drop(key)  # a rule's refusal is already recorded (blocked or declined); a failed check has none
            return f"Verfy stopped this tool call: {reason}"
        result = getattr(context, "tool_result", None)
        if isinstance(result, str) and result.startswith(BLOCKED_PREFIX):
            self.calls.drop(key)  # another hook stopped it: it never ran
            return None
        raw = getattr(context, "raw_tool_result", None)
        try:
            if isinstance(raw, BaseException):
                self.calls.end(key, getattr(context, "tool_name", None), False, raw)
            else:
                self.calls.end(key, getattr(context, "tool_name", None), True, raw if raw is not None else result)
        except Exception:  # noqa: BLE001 - recording after the call never changes its result
            pass
        return None

    def register(self) -> "VerfyCrewHooks":
        """Add these hooks to every tool call CrewAI makes in this process."""
        h = _hooks()
        h.register_before_tool_call_hook(self.before)
        h.register_after_tool_call_hook(self.after)
        return self

    def unregister(self) -> None:
        h = _hooks()
        h.unregister_before_tool_call_hook(self.before)
        h.unregister_after_tool_call_hook(self.after)

    def __enter__(self) -> "VerfyCrewHooks":
        return self.register()

    def __exit__(self, *exc: Any) -> None:
        self.unregister()
