"""Verfy receipts for tool calls made with the OpenAI Agents SDK.

::

    from agents import Agent, Runner
    from verfy import Recorder
    from verfy.integrations.openai_agents import VerfyRunHooks

    hooks = VerfyRunHooks(Recorder("billing-agent", rules=[...]), kinds={"refund": "payment"})
    result = await Runner.run(agent, "Refund order A-1042", hooks=hooks)

Every tool call becomes a signed receipt: the tool's name, its arguments (hashed, unless the recorder stores them;
read from the tool context the SDK passes, when it has them) and "ok" with the hash of the tool's output. With rules,
a call they stop raises ``verfy.ActionDenied`` from ``on_tool_start``: the tool does not run and the run ends with
the SDK's own error, whose cause is the ``ActionDenied``.
Asking a person (``on_ask``) waits in a worker thread, not on the event loop.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from . import ToolCalls
from ..recorder import Recorder

try:  # pragma: no cover - depends on what is installed
    from agents import RunHooks as _Base
except ImportError:  # pragma: no cover
    _Base = object  # type: ignore[assignment,misc]

__all__ = ["VerfyRunHooks"]


def _tool_name(tool: Any) -> str:
    return str(getattr(tool, "name", None) or getattr(tool, "__name__", None) or "tool")


def _arguments(context: Any) -> Any:
    raw = getattr(context, "tool_arguments", None)
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except ValueError:
            return {"arguments": raw}
    return raw if raw is not None else {}


def _call_id(context: Any, agent: Any, tool: Any) -> Any:
    cid = getattr(context, "tool_call_id", None)
    return cid if cid else (id(context), getattr(agent, "name", None), _tool_name(tool))


class VerfyRunHooks(_Base):  # type: ignore[misc,valid-type]
    """Run hooks that record each tool call as a Verfy receipt and check the recorder's rules before it."""

    def __init__(self, recorder: Recorder | None = None, *, system: str = "openai-agents", kinds: dict[str, str] | None = None,
                 kind: str = "other", guard: bool | None = None, record_result: bool = True):
        if _Base is not object:
            super().__init__()
        self.calls = ToolCalls(recorder, system=system, kinds=kinds, kind=kind, guard=guard, record_result=record_result)

    async def on_tool_start(self, context: Any, agent: Any, tool: Any) -> None:
        await asyncio.to_thread(self.calls.start, _call_id(context, agent, tool), _tool_name(tool), _arguments(context))

    async def on_tool_end(self, context: Any, agent: Any, tool: Any, result: Any) -> None:
        self.calls.end(_call_id(context, agent, tool), _tool_name(tool), True, result)

    # the SDK calls these too; when it is not installed there is no base class to supply them
    async def on_agent_start(self, context: Any, agent: Any) -> None:
        return None

    async def on_agent_end(self, context: Any, agent: Any, output: Any) -> None:
        return None

    async def on_handoff(self, context: Any, from_agent: Any, to_agent: Any) -> None:
        return None

    async def on_llm_start(self, context: Any, agent: Any, system_prompt: Any, input_items: Any) -> None:
        return None

    async def on_llm_end(self, context: Any, agent: Any, response: Any) -> None:
        return None
