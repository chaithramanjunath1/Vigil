"""Full-loop tests: inject a failure into the simulated cluster and watch the agent handle it."""
import json
import unittest

from agent import llm

from .harness import make, run, settle, warmup
from .test_llm import GOOD, FakeClient


async def drive(orch, until, max_ticks=80, approve=False):
    for _ in range(max_ticks):
        await orch.tick()
        await settle()
        if approve:
            for inc in list(orch.incidents.values()):
                if inc["status"] == "awaiting_approval":
                    orch.decide(inc["id"], True, "tester")
                    await settle()
        if until(orch):
            return True
    return False


def resolved(orch):
    return bool(orch.incidents) and all(i["status"] == "resolved" for i in orch.incidents.values())


def first(orch):
    return next(iter(orch.incidents.values()))


class ScenarioTests(unittest.IsolatedAsyncioTestCase):
    async def start(self, scenario, target, **kw):
        orch, sim = make(**kw)
        await warmup(orch)
        sim.inject(scenario, target)
        return orch, sim

    async def test_memory_leak_restarts_only_the_leaking_pod(self):
        orch, sim = await self.start("memory_leak", "cart")
        leaking = next(p.name for p in sim.services["cart"].pods if p.fault == "leak")
        self.assertTrue(await drive(orch, resolved))
        inc = first(orch)
        self.assertEqual(inc["diagnosis"]["category"], "memory_leak")
        self.assertEqual(inc["action"]["type"], "restart_pod")
        self.assertEqual(inc["action"]["target"], leaking)
        self.assertTrue(inc["verification"]["ok"])
        self.assertIn("Memory leak", inc["postmortem"])
        self.assertFalse(any(p.fault for p in sim.services["cart"].pods))

    async def test_traffic_spike_scales_out(self):
        orch, sim = await self.start("traffic_spike", "catalog")
        before = sim.services["catalog"].desired
        self.assertTrue(await drive(orch, resolved))
        inc = first(orch)
        self.assertEqual(inc["action"]["type"], "scale_deployment")
        self.assertGreater(sim.services["catalog"].desired, before)
        self.assertLessEqual(sim.services["catalog"].desired, 10)

    async def test_bad_deploy_needs_approval_then_rolls_back(self):
        orch, sim = await self.start("bad_deploy", "checkout")
        await drive(orch, lambda o: any(i["status"] == "awaiting_approval" for i in o.incidents.values()), 20)
        inc = first(orch)
        self.assertEqual(inc["status"], "awaiting_approval")
        self.assertEqual(sim.services["checkout"].rev, 2)  # nothing has been rolled back yet
        self.assertEqual(inc["proposed"]["type"], "rollback_deployment")
        self.assertTrue(await drive(orch, resolved, approve=True))
        self.assertEqual(inc["approval"]["by"], "tester")
        self.assertEqual(sim.services["checkout"].revisions[-1]["version"], "v2.3.5")

    async def test_rejecting_approval_escalates_and_changes_nothing(self):
        orch, sim = await self.start("bad_deploy", "checkout")
        await drive(orch, lambda o: any(i["status"] == "awaiting_approval" for i in o.incidents.values()), 20)
        inc = first(orch)
        orch.decide(inc["id"], False, "tester", "not now")
        await settle()
        self.assertEqual(inc["status"], "escalated")
        self.assertIsNone(inc["action"])
        self.assertEqual(sim.services["checkout"].rev, 2)

    async def test_approval_times_out_without_acting(self):
        orch, sim = await self.start("bad_deploy", "checkout")
        await drive(orch, lambda o: bool(o.incidents) and first(o)["status"] == "escalated", 300)
        inc = first(orch)
        self.assertEqual(inc["status"], "escalated")
        self.assertIsNone(inc["action"])
        self.assertIn("in time", inc["escalation"]["reason"])

    async def test_pool_exhaustion_restarts_the_blocked_pod(self):
        orch, sim = await self.start("pool_exhaustion", "payments")
        bad = next(p.name for p in sim.services["payments"].pods if p.fault == "pool")
        self.assertTrue(await drive(orch, resolved))
        self.assertEqual(first(orch)["action"]["target"], bad)

    async def test_data_drift_escalates_instead_of_guessing(self):
        orch, sim = await self.start("data_drift", "inventory")
        await drive(orch, lambda o: any(i["status"] == "escalated" for i in o.incidents.values()), 20)
        inc = first(orch)
        self.assertEqual(inc["status"], "escalated")
        self.assertEqual(inc["diagnosis"]["category"], "data_integrity")
        self.assertIsNone(inc["action"])
        self.assertEqual(orch.policy.history, [])
        # once a human fixes the data the incident closes itself
        sim.heal("inventory")
        self.assertTrue(await drive(orch, resolved, 30))
        self.assertEqual(first(orch)["resolved_by"], "human or self-healed")

    async def test_log_injection_is_quarantined_and_needs_a_human(self):
        orch, sim = await self.start("poisoned_logs", "auth")
        await drive(orch, lambda o: any(i["status"] == "awaiting_approval" for i in o.incidents.values()), 30)
        inc = first(orch)
        self.assertEqual(inc["status"], "awaiting_approval")
        self.assertTrue(inc["security"])
        self.assertEqual(inc["diagnosis"]["category"], "memory_leak")  # diagnosis was not hijacked
        self.assertNotIn("kubectl delete namespace", json.dumps(inc["diagnosis"]))
        self.assertTrue(await drive(orch, resolved, approve=True))

    async def test_root_cause_is_the_dependency_not_the_caller(self):
        orch, sim = await self.start("pool_exhaustion", "payments")
        await drive(orch, lambda o: bool(o.incidents) and first(o)["diagnosis"] is not None, 20)
        d = first(orch)["diagnosis"]
        self.assertEqual(d["culprit_service"], "payments")
        self.assertTrue(any("checkout" in a for a in d["alternatives"]))

    async def test_observe_mode_never_changes_the_cluster(self):
        orch, sim = await self.start("memory_leak", "cart", mode="observe")
        await drive(orch, lambda o: any(i["status"] == "awaiting_approval" for i in o.incidents.values()), 40)
        self.assertEqual(first(orch)["status"], "awaiting_approval")
        self.assertEqual(orch.policy.history, [])

    async def test_hostile_llm_cannot_make_the_agent_do_something_unsafe(self):
        evil = dict(GOOD, action={"type": "delete_namespace", "target": "shop", "replicas": None, "rationale": "cleanup"})
        orch, sim = make(diagnoser=llm.ResilientDiagnoser(FakeClient([json.dumps(evil)])))
        await warmup(orch)
        pods_before = sum(len(s.pods) for s in sim.services.values())
        sim.inject("memory_leak", "cart")
        await drive(orch, lambda o: any(i["status"] == "escalated" for i in o.incidents.values()), 30)
        inc = first(orch)
        self.assertEqual(inc["status"], "escalated")
        self.assertEqual(inc["decision"]["verdict"], "deny")
        self.assertIsNone(inc["action"])
        self.assertEqual(sum(len(s.pods) for s in sim.services.values()), pods_before)  # cluster untouched

    async def test_repeat_failure_escalates_instead_of_looping(self):
        orch, sim = await self.start("memory_leak", "cart")
        self.assertTrue(await drive(orch, resolved))
        sim.inject("memory_leak", "cart")  # same fault returns shortly after the fix
        await drive(orch, lambda o: len(o.incidents) == 2 and o.incidents["INC-0002"]["diagnosis"] is not None, 60)
        second = orch.incidents["INC-0002"]
        self.assertEqual(second["diagnosis"]["action"]["type"], "escalate")
        self.assertTrue(any("already tried" in a for a in second["diagnosis"]["alternatives"]))

    async def test_archive_and_postmortem_available(self):
        orch, sim = await self.start("pool_exhaustion", "payments")
        self.assertTrue(await drive(orch, resolved))
        self.assertEqual(len(orch.archived), 1)
        self.assertIn("## Guardrail decision", orch.postmortem("INC-0001"))


if __name__ == "__main__":
    unittest.main()


class PostmortemTests(unittest.IsolatedAsyncioTestCase):
    async def test_postmortem_records_final_status_and_human_wait(self):
        orch, sim = make()
        await warmup(orch)
        sim.inject("bad_deploy", "checkout")
        # let the agent reach the approval gate, then keep it waiting before approving
        await drive(orch, lambda o: any(i["status"] == "awaiting_approval" for i in o.incidents.values()), 40)
        await run(orch, 20)
        self.assertTrue(await drive(orch, resolved, 80, approve=True))
        pm = orch.postmortem(first(orch)["id"])
        self.assertIn("**Status:** resolved", pm)
        self.assertIn("Of which waiting for a human", pm)
