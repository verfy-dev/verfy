"""Tests for the LangChain, OpenAI Agents SDK and CrewAI integrations (verfy.integrations). The framework-free tests always run;
the ones that drive the real frameworks run where they are installed. Run from verfy-cli/:
``python -m unittest tests.test_integrations``."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verfy.integrations.crewai import VerfyCrewHooks  # noqa: E402
from verfy.integrations.langchain import VerfyCallbackHandler  # noqa: E402
from verfy.integrations.openai_agents import VerfyRunHooks  # noqa: E402
from verfy.receipts import read_ledger  # noqa: E402
from verfy.recorder import ActionDenied, Recorder  # noqa: E402

HAS_LANGCHAIN = importlib.util.find_spec("langchain_core") is not None
HAS_AGENTS = importlib.util.find_spec("agents") is not None
HAS_CREWAI = importlib.util.find_spec("crewai") is not None
BIG = {"id": "big-refund", "kind": "payment", "amount": "amount", "over": 500, "then": "deny"}


def tmpdir(test: unittest.TestCase) -> Path:
    d = tempfile.TemporaryDirectory()
    test.addCleanup(d.cleanup)
    return Path(d.name)


class LangChainHandler(unittest.TestCase):
    def setUp(self):
        self.rec = Recorder(agent="lc-bot", home=tmpdir(self), upload="off", rules=[BIG])
        self.h = VerfyCallbackHandler(self.rec, kinds={"refund": "payment"})

    def receipts(self):
        return read_ledger(self.rec.ledger_path)

    def test_records_calls_and_errors(self):
        a, b = uuid.uuid4(), uuid.uuid4()
        self.h.on_tool_start({"name": "refund"}, '{"amount": 20}', run_id=a, inputs={"amount": 20, "order": "A-1"})
        self.h.on_tool_start({"name": "lookup"}, "order A-1", run_id=b)
        self.h.on_tool_end("found", run_id=b)
        self.h.on_tool_end({"ok": True}, run_id=a)
        r = self.receipts()
        self.assertEqual([(x["action"]["tool"], x["action"]["kind"], x["action"]["server"]) for x in r],
                         [("lookup", "other", "langchain"), ("refund", "payment", "langchain")])
        self.assertEqual(r[1]["action"]["args_sha256"], self.rec._ledger.hash({"amount": 20, "order": "A-1"}))
        self.assertEqual(r[0]["action"]["args_sha256"], self.rec._ledger.hash({"input": "order A-1"}))
        self.assertEqual(r[1]["decision"]["policy_sha256"], self.rec.rules_sha)
        c = uuid.uuid4()
        self.h.on_tool_start({"name": "lookup"}, "x", run_id=c)
        self.h.on_tool_error(RuntimeError("down"), run_id=c)
        self.assertEqual(self.receipts()[-1]["outcome"]["status"], "error")
        self.assertTrue(self.rec.verify()["ok"])
        self.assertTrue(VerfyCallbackHandler.raise_error)

    def test_a_denied_call_raises_and_is_recorded_once(self):
        run = uuid.uuid4()
        with self.assertRaises(ActionDenied):
            self.h.on_tool_start({"name": "refund"}, "", run_id=run, inputs={"amount": 900})
        self.h.on_tool_error(ActionDenied("x", verdict="deny", findings=[], receipt=None), run_id=run)  # LangChain may report it too
        r = self.receipts()
        self.assertEqual([x["outcome"]["status"] for x in r], ["blocked"])

    @unittest.skipUnless(HAS_LANGCHAIN, "langchain-core is not installed")
    def test_real_langchain_tools(self):
        from langchain_core.tools import tool

        ran = []

        @tool
        def refund(order: str, amount: int) -> str:
            """Refund an order."""
            ran.append(order)
            return f"refunded {order}"

        cfg = {"callbacks": [self.h]}
        self.assertEqual(refund.invoke({"order": "A-1", "amount": 20}, config=cfg), "refunded A-1")
        with self.assertRaises(ActionDenied):
            refund.invoke({"order": "A-2", "amount": 900}, config=cfg)
        self.assertEqual(ran, ["A-1"])
        r = self.receipts()
        self.assertEqual([x["outcome"]["status"] for x in r], ["ok", "blocked"])
        self.assertEqual(r[0]["action"]["args_sha256"], self.rec._ledger.hash({"order": "A-1", "amount": 20}))
        self.assertEqual(r[0]["outcome"]["result_sha256"], self.rec._ledger.hash("refunded A-1"))


class FakeTool:
    def __init__(self, name):
        self.name = name


class FakeContext:
    def __init__(self, call_id, arguments):
        self.tool_call_id, self.tool_arguments = call_id, arguments


class AgentsHooks(unittest.TestCase):
    def setUp(self):
        self.rec = Recorder(agent="oa-bot", home=tmpdir(self), upload="off", rules=[BIG])
        self.hooks = VerfyRunHooks(self.rec, kinds={"refund": "payment"})

    def test_records_parallel_calls(self):
        async def go():
            t = FakeTool("refund")
            c1, c2 = FakeContext("call_1", '{"amount": 10}'), FakeContext("call_2", '{"amount": 30}')
            await self.hooks.on_tool_start(c1, None, t)
            await self.hooks.on_tool_start(c2, None, t)
            await self.hooks.on_tool_end(c2, None, t, "ok 30")
            await self.hooks.on_tool_end(c1, None, t, "ok 10")
            with self.assertRaises(ActionDenied):
                await self.hooks.on_tool_start(FakeContext("call_3", '{"amount": 900}'), None, t)
            for name in ("on_agent_start", "on_handoff"):
                self.assertTrue(hasattr(self.hooks, name))
        asyncio.run(go())
        r = read_ledger(self.rec.ledger_path)
        self.assertEqual([x["outcome"]["status"] for x in r], ["ok", "ok", "blocked"])
        self.assertEqual(r[0]["action"]["args_sha256"], self.rec._ledger.hash({"amount": 30}))
        self.assertEqual(r[0]["outcome"]["result_sha256"], self.rec._ledger.hash("ok 30"))
        self.assertEqual(r[0]["action"]["kind"], "payment")

    @unittest.skipUnless(HAS_AGENTS, "openai-agents is not installed")
    def test_a_real_agents_run(self):
        import os
        os.environ.setdefault("OPENAI_AGENTS_DISABLE_TRACING", "1")
        from agents import Agent, ModelResponse, RunConfig, Runner, Usage, function_tool
        from agents.lifecycle import RunHooksBase
        from agents.models.interface import Model
        from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText

        self.assertIsInstance(self.hooks, RunHooksBase)

        class OneToolCall(Model):  # asks for one refund, then answers; no network
            def __init__(self, amount):
                self.turn, self.amount = 0, amount

            async def get_response(self, *args, **kwargs):
                self.turn += 1
                if self.turn == 1:
                    out = [ResponseFunctionToolCall(id="fc_1", call_id="call_1", name="refund", type="function_call", status="completed",
                                                    arguments='{"order": "A-1", "amount": %d}' % self.amount)]
                else:
                    out = [ResponseOutputMessage(id="m1", role="assistant", status="completed", type="message",
                                                 content=[ResponseOutputText(text="done", type="output_text", annotations=[])])]
                return ModelResponse(output=out, usage=Usage(), response_id=None)

            def stream_response(self, *args, **kwargs):
                raise NotImplementedError

        ran = []

        @function_tool
        def refund(order: str, amount: int) -> str:
            """Refund an order."""
            ran.append(order)
            return f"refunded {order}"

        cfg = RunConfig(tracing_disabled=True)

        async def go():
            ok = await Runner.run(Agent(name="billing", tools=[refund], model=OneToolCall(20)), "refund", hooks=self.hooks, run_config=cfg)
            self.assertEqual(ok.final_output, "done")
            with self.assertRaises(Exception) as cm:  # the SDK raises it as its own error, caused by ActionDenied
                await Runner.run(Agent(name="billing", tools=[refund], model=OneToolCall(900)), "refund", hooks=self.hooks, run_config=cfg)
            chain, e = [], cm.exception
            while e is not None:
                chain.append(e)
                e = e.__cause__ or e.__context__
            self.assertTrue(any(isinstance(x, ActionDenied) for x in chain), chain)
        asyncio.run(go())
        self.assertEqual(ran, ["A-1"])
        r = read_ledger(self.rec.ledger_path)
        self.assertEqual([x["outcome"]["status"] for x in r], ["ok", "blocked"])
        self.assertEqual(r[0]["action"]["args_sha256"], self.rec._ledger.hash({"order": "A-1", "amount": 20}))
        self.assertEqual(r[0]["outcome"]["result_sha256"], self.rec._ledger.hash("refunded A-1"))


class CrewContext:
    """What CrewAI passes a tool-call hook: a new object for before and after, the same input dict in both."""

    def __init__(self, name, tool_input, tool_result=None, raw_tool_result=None):
        self.tool_name, self.tool_input, self.tool_result, self.raw_tool_result = name, tool_input, tool_result, raw_tool_result


class CrewHooks(unittest.TestCase):
    def setUp(self):
        self.rec = Recorder(agent="crew-bot", home=tmpdir(self), upload="off", rules=[BIG])
        self.hooks = VerfyCrewHooks(self.rec, kinds={"refund": "payment"})

    def call(self, name, data, result="ok", raw=None):
        allowed = self.hooks.before(CrewContext(name, data))
        replaced = self.hooks.after(CrewContext(name, data, result if allowed is not False else "Tool execution blocked by hook. Tool: " + name,
                                                raw if allowed is not False else None))
        return allowed, replaced

    def statuses(self):
        return [r["outcome"]["status"] for r in read_ledger(self.rec.ledger_path)]

    def test_records_calls_and_blocks_what_the_rules_stop(self):
        self.assertEqual(self.call("refund", {"order": "A-1", "amount": 20}, "refunded", "refunded"), (None, None))
        allowed, replaced = self.call("refund", {"order": "A-2", "amount": 900})
        self.assertIs(allowed, False)
        self.assertIn("Verfy stopped this tool call", replaced)
        self.assertEqual(self.call("lookup", {"q": "x"}, "boom", RuntimeError("down")), (None, None))
        self.assertEqual(self.statuses(), ["ok", "blocked", "error"])
        r = read_ledger(self.rec.ledger_path)[0]
        self.assertEqual((r["action"]["tool"], r["action"]["kind"], r["action"]["server"]), ("refund", "payment", "crewai"))
        self.assertEqual(r["action"]["args_sha256"], self.rec._ledger.hash({"order": "A-1", "amount": 20}))

    def test_a_check_that_fails_blocks_the_call(self):
        with mock.patch.object(self.rec, "_guard", side_effect=RuntimeError("state unreadable")):
            allowed, replaced = self.call("refund", {"order": "A-3", "amount": 1})
        self.assertIs(allowed, False)  # CrewAI would run the tool if the hook raised
        self.assertIn("did not run", replaced)
        self.assertEqual(self.statuses(), [])

    def test_a_call_another_hook_stopped_is_not_recorded(self):
        data = {"order": "A-4", "amount": 5}
        self.assertIsNone(self.hooks.before(CrewContext("refund", data)))
        self.assertIsNone(self.hooks.after(CrewContext("refund", data, "Tool execution blocked by hook. Tool: refund")))
        self.assertEqual(self.statuses(), [])

    @unittest.skipUnless(HAS_CREWAI, "crewai is not installed")
    def test_a_real_crew(self):
        import os
        os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
        os.environ.setdefault("OTEL_SDK_DISABLED", "true")
        os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")
        from crewai import Agent, BaseLLM, Crew, Task, hooks
        from crewai.tools import tool

        ran = []

        @tool("refund")
        def refund(order: str, amount: int) -> str:
            """Refund an order."""
            ran.append(order)
            return f"refunded {order}"

        class OneToolCall(BaseLLM):  # asks for one refund, then answers; no network
            amount: int = 20
            turn: int = 0
            seen: list = []

            def call(self, messages, tools=None, callbacks=None, available_functions=None, from_task=None, from_agent=None, response_model=None):
                self.turn += 1
                self.seen = [*self.seen, str(messages)]
                if self.turn == 1:
                    return 'Thought: refund it.\nAction: refund\nAction Input: {"order": "A-1", "amount": %d}' % self.amount
                return "Thought: I know the final answer.\nFinal Answer: done"

            def supports_function_calling(self) -> bool:
                return False

            def supports_stop_words(self) -> bool:
                return False

            def get_context_window_size(self) -> int:
                return 8192

        def run(amount):
            llm = OneToolCall(model="fake-model", amount=amount)
            agent = Agent(role="billing", goal="refund orders", backstory="x", tools=[refund], llm=llm, verbose=False, max_iter=3)
            out = Crew(agents=[agent], tasks=[Task(description="Refund A-1", expected_output="done", agent=agent)], verbose=False).kickoff()
            return str(out), " ".join(llm.seen)

        with self.hooks:
            self.assertEqual(run(20)[0], "done")
            out, seen = run(900)
        self.assertEqual(ran, ["A-1"])  # the big refund never ran
        self.assertIn("Verfy stopped this tool call", seen)  # and the agent read why
        self.assertEqual(self.statuses(), ["ok", "blocked"])
        r = read_ledger(self.rec.ledger_path)[0]
        self.assertEqual(r["action"]["args_sha256"], self.rec._ledger.hash({"order": "A-1", "amount": 20}))
        self.assertEqual(r["outcome"]["result_sha256"], self.rec._ledger.hash("refunded A-1"))
        self.assertEqual((len(hooks.get_before_tool_call_hooks()), len(hooks.get_after_tool_call_hooks())), (0, 0))

    def test_without_crewai_register_says_how_to_get_it(self):
        if HAS_CREWAI:
            self.skipTest("crewai is installed")
        with self.assertRaisesRegex(ImportError, "pip install crewai"):
            self.hooks.register()


if __name__ == "__main__":
    unittest.main()
