"""The real-cluster backend, exercised against a fake Kubernetes API and fake Prometheus."""
import asyncio
import json
import unittest
from urllib.parse import parse_qs, urlsplit

from agent.backend import BackendError
from agent.config import Settings, load_spec
from agent.k8s_backend import KubernetesBackend, parse_quantity

NS = "shop"


def pod(name, app, phase="Running", ready=True, restarts=0, waiting=None, oom=False, mem="512Mi", image="reg/cart:v1.14.2"):
    cs = {"restartCount": restarts, "ready": ready, "state": {}, "lastState": {}}
    if waiting:
        cs["state"] = {"waiting": {"reason": waiting}}
    if oom:
        cs["lastState"] = {"terminated": {"reason": "OOMKilled"}}
    return {"metadata": {"name": name, "labels": {"app": app}},
            "spec": {"containers": [{"name": "c", "image": image, "resources": {"limits": {"memory": mem, "cpu": "500m"}}}]},
            "status": {"phase": phase, "containerStatuses": [cs],
                       "conditions": [{"type": "Ready", "status": "True" if ready else "False"}]}}


def rs(name, deployment, revision, image, hash_):
    return {"metadata": {"name": name, "ownerReferences": [{"name": deployment}],
                         "annotations": {"deployment.kubernetes.io/revision": str(revision), "kubernetes.io/change-cause": f"deploy {image}"}},
            "spec": {"template": {"metadata": {"labels": {"app": deployment, "pod-template-hash": hash_}},
                                  "spec": {"containers": [{"name": "c", "image": image}]}}}}


class FakeCluster:
    def __init__(self):
        self.calls = []
        self.prom_down = False
        self.pods = [
            pod("cart-aaa-1", "cart"), pod("cart-aaa-2", "cart", restarts=2, ready=False, oom=True),
            pod("checkout-bbb-1", "checkout", ready=False, waiting="CrashLoopBackOff", restarts=5, image="reg/checkout:v2.4.0"),
        ]

    def dep(self, name, replicas, revision, image):
        return {"metadata": {"name": name, "annotations": {"deployment.kubernetes.io/revision": str(revision)}},
                "spec": {"replicas": replicas, "selector": {"matchLabels": {"app": name}},
                         "template": {"spec": {"containers": [{"name": "c", "image": image}]}}}}

    def http(self, method, url, body=None, content_type="application/json"):
        path = urlsplit(url).path
        self.calls.append((method, path, body, content_type))
        if "prom" in urlsplit(url).netloc:
            if self.prom_down:
                raise BackendError("cannot reach prometheus")
            q = parse_qs(urlsplit(url).query)["query"][0]
            val = []
            if q.startswith("sum by (service)(rate(http_requests_total{namespace") and "5.." not in q:
                val = [{"metric": {"service": "cart"}, "value": [0, "42.5"]}]
            elif "5.." in q:
                val = [{"metric": {"service": "cart"}, "value": [0, "0.02"]}, {"metric": {"service": "checkout"}, "value": [0, "NaN"]}]
            elif "histogram_quantile" in q:
                val = [{"metric": {"service": "cart"}, "value": [0, "123.4"]}]
            elif "container_memory" in q:
                val = [{"metric": {"pod": "cart-aaa-1"}, "value": [0, str(256 * 1024 ** 2)]},
                       {"metric": {"pod": "cart-aaa-2"}, "value": [0, str(500 * 1024 ** 2)]}]
            elif "container_cpu" in q:
                val = [{"metric": {"pod": "cart-aaa-1"}, "value": [0, "0.25"]}]
            return {"status": "success", "data": {"result": val}}
        if method == "GET" and path.endswith("/pods"):
            return {"items": self.pods}
        if method == "GET" and path.endswith("/deployments"):
            return {"items": [self.dep("cart", 2, 3, "reg/cart:v1.14.2"), self.dep("checkout", 1, 4, "reg/checkout:v2.4.0")]}
        if method == "GET" and "/deployments/" in path:
            name = path.rsplit("/", 1)[1]
            return self.dep(name, 1, 4, "reg/checkout:v2.4.0")
        if method == "GET" and path.endswith("/replicasets"):
            return {"items": [rs("checkout-new", "checkout", 4, "reg/checkout:v2.4.0", "h2"),
                              rs("checkout-old", "checkout", 3, "reg/checkout:v2.3.5", "h1"),
                              rs("other-rs", "payments", 9, "reg/payments:v9", "h9")]}
        if method == "GET" and path.endswith("/log"):
            return "INFO started\nERROR panic: bad config\nWARN back-off\n"
        return {}


def make(cluster=None):
    spec = load_spec()
    settings = Settings(namespace=NS, poll_seconds=0.01, prometheus_url="http://prom:9090")
    c = cluster or FakeCluster()
    b = KubernetesBackend(spec, settings, http=c.http)
    b.api = "http://kube"
    return b, c


def run(coro):
    return asyncio.run(coro)


class QuantityTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_quantity("500m"), 0.5)
        self.assertEqual(parse_quantity("512Mi"), 512 * 1024 ** 2)
        self.assertEqual(parse_quantity("1"), 1.0)
        self.assertEqual(parse_quantity(None, 7), 7)


class SnapshotTests(unittest.TestCase):
    def test_reads_pods_metrics_and_health(self):
        b, _ = make()
        snap = run(b.snapshot())
        by = {s["name"]: s for s in snap["services"]}
        self.assertEqual(set(by), {"cart", "checkout"})  # only deployments that exist
        cart = by["cart"]
        self.assertEqual((cart["desired"], cart["ready"]), (2, 1))
        self.assertEqual(cart["rps"], 42.5)
        self.assertEqual(cart["p95_ms"], 123.4)
        self.assertAlmostEqual(cart["error_rate"], 0.02)
        pods = {p["name"]: p for p in cart["pods"]}
        self.assertEqual(pods["cart-aaa-1"]["mem_pct"], 50.0)
        self.assertEqual(pods["cart-aaa-1"]["cpu_pct"], 50.0)
        self.assertEqual(pods["cart-aaa-2"]["status"], "OOMKilled")
        self.assertEqual(pods["cart-aaa-2"]["restarts"], 2)
        self.assertEqual(cart["revision"], 3)
        self.assertEqual(cart["version"], "v1.14.2")
        co = by["checkout"]
        self.assertEqual(co["pods"][0]["status"], "CrashLoopBackOff")
        self.assertEqual(co["health"], "critical")  # no ready pods
        self.assertTrue(snap["edges"])

    def test_survives_prometheus_outage(self):
        c = FakeCluster()
        c.prom_down = True
        b, _ = make(c)
        snap = run(b.snapshot())
        self.assertEqual(len(snap["services"]), 2)
        self.assertEqual(snap["services"][0]["rps"], 0.0)

    def test_advance_bumps_clock(self):
        b, _ = make()
        snap = run(b.advance())
        self.assertEqual(snap["tick"], 1)
        self.assertEqual(b.clock.tick, 1)


class LogAndHistoryTests(unittest.TestCase):
    def test_logs_classified(self):
        b, _ = make()
        run(b.snapshot())
        lines = run(b.logs("checkout", 10))
        levels = [ln["level"] for ln in lines]
        self.assertEqual(levels, ["INFO", "ERROR", "WARN"])
        self.assertEqual(lines[0]["service"], "checkout")
        with self.assertRaises(BackendError):
            run(b.logs("nope"))

    def test_deployment_history_only_owned_replicasets(self):
        b, _ = make()
        hist = run(b.deployments())
        revs = [r["version"] for r in hist["checkout"]]
        self.assertEqual(revs, ["v2.3.5", "v2.4.0"])


class ActionTests(unittest.TestCase):
    def test_restart_deletes_pod(self):
        b, c = make()
        res = run(b.restart_pod(NS, "cart-aaa-2"))
        self.assertTrue(res["ok"])
        self.assertIn(("DELETE", f"/api/v1/namespaces/{NS}/pods/cart-aaa-2", None, "application/json"), c.calls)

    def test_scale_patches_scale_subresource(self):
        b, c = make()
        run(b.scale_deployment(NS, "cart", 5))
        method, path, body, ctype = [x for x in c.calls if x[0] == "PATCH"][0]
        self.assertTrue(path.endswith("/deployments/cart/scale"))
        self.assertEqual(body, {"spec": {"replicas": 5}})
        self.assertEqual(ctype, "application/merge-patch+json")

    def test_rollback_reapplies_previous_template_without_hash(self):
        b, c = make()
        res = run(b.rollback_deployment(NS, "checkout"))
        self.assertIn("v2.3.5", res["detail"])
        method, path, body, ctype = [x for x in c.calls if x[0] == "PATCH"][0]
        tpl = body["spec"]["template"]
        self.assertEqual(tpl["spec"]["containers"][0]["image"], "reg/checkout:v2.3.5")
        self.assertNotIn("pod-template-hash", tpl["metadata"]["labels"])
        self.assertEqual(ctype, "application/strategic-merge-patch+json")

    def test_refuses_other_namespaces_and_unmanaged_deployments(self):
        b, c = make()
        for coro in (b.restart_pod("kube-system", "x"), b.scale_deployment("kube-system", "cart", 2),
                     b.rollback_deployment("kube-system", "cart")):
            with self.assertRaises(BackendError):
                run(coro)
        with self.assertRaises(BackendError):
            run(b.scale_deployment(NS, "coredns", 2))
        self.assertEqual([x for x in c.calls if x[0] in ("DELETE", "PATCH")], [])


if __name__ == "__main__":
    unittest.main()
