import copy
import unittest

from agent.config import load_spec
from agent.policy import PolicyEngine


def snap_with(desired=3, ready=3, revision=1):
    pods = [{"name": f"cart-aaa-{i}", "ready": i < ready, "status": "Running" if i < ready else "Pending"} for i in range(desired)]
    return {"tick": 100, "services": [
        {"name": "cart", "desired": desired, "ready": ready, "revision": revision, "pods": pods},
        {"name": "auth", "desired": 1, "ready": 1, "revision": 1, "pods": [{"name": "auth-aaa-0", "ready": True, "status": "Running"}]},
    ]}


def diag(atype, target, replicas=None, conf=0.9):
    return {"confidence": conf, "action": {"type": atype, "target": target, "replicas": replicas, "rationale": ""}}


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.spec = load_spec()
        self.p = PolicyEngine(self.spec, mode="auto")

    def test_unlisted_action_is_denied(self):
        for bad in ("delete_namespace", "exec", "kubectl_delete_all", "drain_node"):
            d = self.p.evaluate(diag(bad, "cart"), snap_with(), 100)
            self.assertEqual(d.verdict, "deny", bad)
            self.assertFalse(d.checks[0].passed)

    def test_unknown_target_is_denied(self):
        d = self.p.evaluate(diag("restart_pod", "kube-apiserver-0"), snap_with(), 100)
        self.assertEqual(d.verdict, "deny")

    def test_wrong_target_type_is_denied(self):
        self.assertEqual(self.p.evaluate(diag("restart_pod", "cart"), snap_with(), 100).verdict, "deny")
        self.assertEqual(self.p.evaluate(diag("scale_deployment", "cart-aaa-0", 4), snap_with(), 100).verdict, "deny")

    def test_restart_allowed_when_capacity_remains(self):
        self.assertEqual(self.p.evaluate(diag("restart_pod", "cart-aaa-0"), snap_with(), 100).verdict, "allow")

    def test_restart_denied_when_it_would_drop_below_floor(self):
        d = self.p.evaluate(diag("restart_pod", "cart-aaa-0"), snap_with(desired=4, ready=2), 100)
        self.assertEqual(d.verdict, "deny")
        self.assertIn("availability floor", [c.name for c in d.checks if not c.passed])

    def test_scale_is_clamped_to_safe_bounds(self):
        d = self.p.evaluate(diag("scale_deployment", "cart", 50), snap_with(desired=3), 100)
        self.assertEqual(d.verdict, "allow")
        self.assertEqual(d.action["replicas"], 7)  # floor(3 * 2.5)

    def test_scale_to_current_count_is_pointless(self):
        self.assertEqual(self.p.evaluate(diag("scale_deployment", "cart", 3), snap_with(), 100).verdict, "deny")

    def test_rollback_always_needs_approval(self):
        d = self.p.evaluate(diag("rollback_deployment", "cart"), snap_with(revision=2), 100)
        self.assertEqual(d.verdict, "approve")

    def test_rollback_without_history_is_denied(self):
        self.assertEqual(self.p.evaluate(diag("rollback_deployment", "cart"), snap_with(revision=1), 100).verdict, "deny")

    def test_low_confidence_needs_approval(self):
        self.assertEqual(self.p.evaluate(diag("restart_pod", "cart-aaa-0", conf=0.5), snap_with(), 100).verdict, "approve")

    def test_quarantined_logs_force_human_gate(self):
        d = self.p.evaluate(diag("restart_pod", "cart-aaa-0"), snap_with(), 100, quarantined=2)
        self.assertEqual(d.verdict, "approve")
        self.assertIn("untrusted input", [c.name for c in d.checks if not c.passed])

    def test_cooldown_blocks_back_to_back_actions(self):
        self.p.record(95, "cart", "restart_pod")
        self.assertEqual(self.p.evaluate(diag("restart_pod", "cart-aaa-1"), snap_with(), 100).verdict, "deny")
        self.assertEqual(self.p.evaluate(diag("restart_pod", "cart-aaa-1"), snap_with(), 200).verdict, "allow")

    def test_rate_limit_stops_flapping(self):
        for i, svc in enumerate(["a", "b", "c", "d"]):
            self.p.record(60 + i, svc, "restart_pod")
        d = self.p.evaluate(diag("restart_pod", "cart-aaa-0"), snap_with(), 100)
        self.assertEqual(d.verdict, "deny")
        self.assertIn("rate limit", [c.name for c in d.checks if not c.passed])

    def test_modes(self):
        self.p.mode = "observe"
        self.assertEqual(self.p.evaluate(diag("restart_pod", "cart-aaa-0"), snap_with(), 100).verdict, "approve")
        self.p.mode = "approve"
        self.assertEqual(self.p.evaluate(diag("restart_pod", "cart-aaa-0"), snap_with(), 100).verdict, "approve")

    def test_human_approval_still_runs_hard_checks(self):
        d = self.p.evaluate(diag("delete_namespace", "shop"), snap_with(), 100, human_approved=True)
        self.assertEqual(d.verdict, "deny")
        d = self.p.evaluate(diag("rollback_deployment", "cart"), snap_with(revision=2), 100, human_approved=True)
        self.assertEqual(d.verdict, "allow")

    def test_escalate_never_touches_cluster(self):
        self.assertEqual(self.p.evaluate(diag("escalate", "inventory"), snap_with(), 100).verdict, "allow")


if __name__ == "__main__":
    unittest.main()
