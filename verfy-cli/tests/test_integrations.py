"""Tests for the LangChain and OpenAI Agents SDK integrations (verfy.integrations). The framework-free tests always run;
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

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verfy.integrations.langchain import VerfyCallbackHandler  # noqa: E402
from verfy.integrations.openai_agents import VerfyRunHooks  # noqa: E402
from verfy.receipts import read_ledger  # noqa: E402
from verfy.recorder import ActionDenied, Recorder  # noqa: E402

HAS_LANGCHAIN = importlib.util.find_spec("langchain_core") is not None
HAS_AGENTS = importlib.util.find_spec("agents") is not None
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


if __name__ == "__main__":
    unittest.main()
