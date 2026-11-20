"""Verfy receipts for LangChain and LangGraph tool calls.

::

    from verfy import Recorder
    from verfy.integrations.langchain import VerfyCallbackHandler

    handler = VerfyCallbackHandler(Recorder("support-agent", rules=[...]), kinds={"refund": "payment"})
    agent.invoke({"input": "..."}, config={"callbacks": [handler]})

Every tool call becomes a signed receipt: the tool's name, its input (hashed, unless the recorder stores arguments)
and "ok" with the hash of its output, or "error". With rules, a call they stop raises ``verfy.ActionDenied`` before
the tool runs (the handler sets ``raise_error``, so LangChain passes the exception up instead of logging it).
"""

from __future__ import annotations

import json
from typing import Any

from . import ToolCalls
from ..recorder import Recorder

try:  # pragma: no cover - depends on what is installed
    from langchain_core.callbacks import BaseCallbackHandler as _Base
except ImportError:  # pragma: no cover
    _Base = object  # type: ignore[assignment,misc]

__all__ = ["VerfyCallbackHandler"]


def _input(input_str: Any, inputs: Any) -> Any:
    if isinstance(inputs, dict):
        return inputs
    if isinstance(input_str, str):
        try:
            parsed = json.loads(input_str)
            if isinstance(parsed, dict):
                return parsed
        except ValueError:
            pass
        return {"input": input_str}
    return {"input": input_str}


def _output(output: Any) -> Any:
    content = getattr(output, "content", None)  # a ToolMessage
    return content if content is not None else output


class VerfyCallbackHandler(_Base):  # type: ignore[misc,valid-type]
    """Records LangChain tool calls as Verfy receipts and checks the recorder's rules before each one."""

    raise_error = True  # a denied call must stop the tool, not be logged and ignored
    run_inline = True  # guard in the same thread, before the tool runs

    def __init__(self, recorder: Recorder | None = None, *, system: str = "langchain", kinds: dict[str, str] | None = None,
                 kind: str = "other", guard: bool | None = None, record_result: bool = True):
        if _Base is not object:
            super().__init__()
        self.calls = ToolCalls(recorder, system=system, kinds=kinds, kind=kind, guard=guard, record_result=record_result)

    def on_tool_start(self, serialized: dict[str, Any] | None, input_str: str, *, run_id: Any = None, inputs: dict | None = None,
                      **kwargs: Any) -> None:
        name = (serialized or {}).get("name") or kwargs.get("name") or "tool"
        self.calls.start(run_id, str(name), _input(input_str, inputs))

    def on_tool_end(self, output: Any, *, run_id: Any = None, **kwargs: Any) -> None:
        self.calls.end(run_id, kwargs.get("name"), True, _output(output))

    def on_tool_error(self, error: BaseException, *, run_id: Any = None, **kwargs: Any) -> None:
        self.calls.end(run_id, kwargs.get("name"), False, error)
