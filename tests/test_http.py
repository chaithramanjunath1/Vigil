"""Real HTTP against the stdlib server: routes, SSE, auth, webhook, static files, abuse limits."""
import asyncio
import json
import tempfile
import unittest
import urllib.error
import urllib.request

from agent.alerts import to_alertmanager
from agent.config import Settings
from agent.lite_server import LiteServer


def settings(**kw):
    s = Settings(tick_seconds=0.02, speed=1.0, data_dir=tempfile.mkdtemp())
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def req(base, method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(base + path, data=data, method=method, headers={"Content-Type": "application/json"})
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, resp.read(), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers


async def call(*a, **kw):
    return await asyncio.to_thread(req, *a, **kw)


async def jcall(*a, **kw):
    status, body, _ = await call(*a, **kw)
    return status, (json.loads(body) if body else None)


async def wait_for(cond, timeout=20):
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if await cond():
            return True
        await asyncio.sleep(0.05)
    return False


class HttpTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.srv = LiteServer(settings())
        port = await self.srv.start("127.0.0.1", 0)
        self.base = f"http://127.0.0.1:{port}"
        await wait_for(self._warm)

    async def asyncTearDown(self):
        await self.srv.stop()

    async def _warm(self):
        return len(self.srv.orch.history.baselines) == 8

    async def test_health_state_and_dashboard_files(self):
        s, h = await jcall(self.base, "GET", "/healthz")
        self.assertEqual((s, h["status"]), (200, "ok"))
        s, st = await jcall(self.base, "GET", "/api/state")
        self.assertEqual(len(st["snapshot"]["services"]), 8)
        self.assertEqual(len(st["scenarios"]), 6)
        s, body, hdr = await call(self.base, "GET", "/scenarios.json")
        self.assertEqual(s, 200)
        self.assertIn("application/json", hdr["Content-Type"])

    async def test_static_path_traversal_is_blocked(self):
        for p in ("/../agent/config.py", "/..%2fagent/config.py", "/%2e%2e/agent/config.py"):
            s, body, _ = await call(self.base, "GET", p)
            self.assertIn(s, (403, 404), p)
            self.assertNotIn(b"class Settings", body)

    async def test_unknown_route_and_bad_input(self):
        self.assertEqual((await jcall(self.base, "GET", "/api/nope"))[0], 404)
        self.assertEqual((await jcall(self.base, "POST", "/api/mode", {"mode": "yolo"}))[0], 400)
        s, body, _ = await call(self.base, "POST", "/api/mode")
        self.assertEqual(s, 400)  # empty body means no mode given
        r = urllib.request.Request(self.base + "/api/chaos", data=b"{not json", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            await asyncio.to_thread(urllib.request.urlopen, r)
        self.assertEqual(cm.exception.code, 400)

    async def test_chaos_to_resolution_over_http(self):
        s, res = await jcall(self.base, "POST", "/api/chaos", {"scenario": "pool_exhaustion", "target": "payments"})
        self.assertEqual((s, res["target"]), (200, "payments"))

        async def done():
            _, incs = await jcall(self.base, "GET", "/api/incidents")
            return bool(incs) and all(i["status"] == "resolved" for i in incs)

        self.assertTrue(await wait_for(done))
        _, incs = await jcall(self.base, "GET", "/api/incidents")
        iid = incs[0]["id"]
        s, md, hdr = await call(self.base, "GET", f"/api/incidents/{iid}/postmortem")
        self.assertEqual(s, 200)
        self.assertIn("text/markdown", hdr["Content-Type"])
        self.assertIn(b"Root cause", md)
        s, text = await jcall(self.base, "GET", "/metrics") if False else (None, None)
        s, body, _ = await call(self.base, "GET", "/metrics")
        self.assertIn(b"vigil_actions_total", body)

    async def test_approval_flow_over_http(self):
        await jcall(self.base, "POST", "/api/mode", {"mode": "approve"})
        await jcall(self.base, "POST", "/api/chaos", {"scenario": "memory_leak", "target": "cart"})

        async def waiting():
            _, incs = await jcall(self.base, "GET", "/api/incidents")
            return any(i["status"] == "awaiting_approval" for i in incs)

        self.assertTrue(await wait_for(waiting, 40))
        _, incs = await jcall(self.base, "GET", "/api/incidents")
        iid = next(i["id"] for i in incs if i["status"] == "awaiting_approval")
        s, _ = await jcall(self.base, "POST", f"/api/incidents/{iid}/approve", {"by": "chaithra"})
        self.assertEqual(s, 200)
        s, _ = await jcall(self.base, "POST", f"/api/incidents/{iid}/approve", {"by": "chaithra"})
        self.assertEqual(s, 409)  # already decided

        async def done():
            return self.srv.orch.incidents[iid]["status"] == "resolved"

        self.assertTrue(await wait_for(done, 30))
        self.assertEqual(self.srv.orch.incidents[iid]["approval"]["by"], "chaithra")

    async def test_chaos_is_rate_limited(self):
        s1, _ = await jcall(self.base, "POST", "/api/chaos", {"scenario": "traffic_spike", "target": "auth"})
        s2, _ = await jcall(self.base, "POST", "/api/chaos", {"scenario": "traffic_spike", "target": "catalog"})
        self.assertEqual((s1, s2), (200, 429))

    async def test_alertmanager_webhook_opens_incident(self):
        payload = to_alertmanager([{"name": "HighErrorRate", "service": "cart", "pod": None, "severity": "critical",
                                    "summary": "cart errors", "status": "firing", "fingerprint": "ext-1"}], "shop")
        s, res = await jcall(self.base, "POST", "/webhook/alertmanager", payload)
        self.assertEqual((s, res["fired"]), (200, 1))
        s, res = await jcall(self.base, "POST", "/webhook/alertmanager", payload)
        self.assertEqual(res["fired"], 0)  # duplicate fingerprint is not re-fired
        self.assertEqual(len(self.srv.orch.incidents), 1)

    async def test_webhook_ignores_unknown_services(self):
        payload = {"alerts": [{"status": "firing", "labels": {"alertname": "X", "service": "not-ours"}, "annotations": {}}]}
        _, res = await jcall(self.base, "POST", "/webhook/alertmanager", payload)
        self.assertEqual(res["fired"], 0)

    async def test_sse_stream_delivers_state_then_ticks(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", int(self.base.rsplit(":", 1)[1]))
        writer.write(b"GET /api/stream HTTP/1.1\r\nHost: x\r\n\r\n")
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        self.assertIn(b"text/event-stream", head)
        seen = []
        buf = b""
        while len(seen) < 3:
            buf += await asyncio.wait_for(reader.read(65536), 5)
            while b"\n\n" in buf:
                block, buf = buf.split(b"\n\n", 1)
                if block.startswith(b"event:"):
                    seen.append(block.split(b"\n", 1)[0].decode())
        writer.close()
        self.assertEqual(seen[0], "event: state")
        self.assertIn("event: tick", seen[1:])
        await asyncio.sleep(0.1)
        self.assertEqual(len(self.srv.orch._subs), 0)  # subscriber cleaned up on disconnect


class AuthTests(unittest.IsolatedAsyncioTestCase):
    async def test_post_requires_token_when_configured(self):
        srv = LiteServer(settings(api_token="s3cret"))
        port = await srv.start("127.0.0.1", 0)
        base = f"http://127.0.0.1:{port}"
        try:
            self.assertEqual((await jcall(base, "GET", "/api/state"))[0], 200)  # reads stay open
            self.assertEqual((await jcall(base, "POST", "/api/mode", {"mode": "observe"}))[0], 401)
            self.assertEqual((await jcall(base, "POST", "/api/mode", {"mode": "observe"}, token="wrong"))[0], 401)
            self.assertEqual((await jcall(base, "POST", "/api/mode", {"mode": "observe"}, token="s3cret"))[0], 200)
        finally:
            await srv.stop()

    async def test_chaos_can_be_disabled(self):
        srv = LiteServer(settings(allow_chaos=False))
        port = await srv.start("127.0.0.1", 0)
        try:
            s, _ = await jcall(f"http://127.0.0.1:{port}", "POST", "/api/chaos", {"scenario": "memory_leak"})
            self.assertEqual(s, 403)
        finally:
            await srv.stop()


if __name__ == "__main__":
    unittest.main()
