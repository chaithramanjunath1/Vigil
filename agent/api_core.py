"""All HTTP route logic, independent of any web framework.

Both adapters (FastAPI in app.py and the stdlib server in lite_server.py) call
`Api.handle(...)`, so the behaviour is tested once and identical everywhere.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import re
import time
from urllib.parse import parse_qs, urlsplit

from .alerts import parse_alertmanager
from .backend import BackendError

JSON = "application/json"
MAX_SSE_CLIENTS = 100


class ApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status, self.message = status, message


def _json(obj) -> bytes:
    return json.dumps(obj, default=str, separators=(",", ":")).encode()


class Api:
    def __init__(self, orch, settings) -> None:
        self.orch = orch
        self.settings = settings
        self._last_chaos = 0.0
        self._last_reset = 0.0

    # ----------------------------------------------------------------- dispatch
    async def handle(self, method: str, target: str, body: bytes = b"", headers: dict | None = None) -> tuple[int, str, bytes]:
        """Returns (status, content_type, body)."""
        headers = {k.lower(): v for k, v in (headers or {}).items()}
        parts = urlsplit(target)
        path, query = parts.path.rstrip("/") or "/", {k: v[0] for k, v in parse_qs(parts.query).items()}
        try:
            if method == "OPTIONS":
                return 204, JSON, b""
            data = self._parse_body(body) if method in ("POST", "PUT") else {}
            if method == "POST":
                self._require_auth(headers)
            result = await self._route(method, path, query, data)
            if isinstance(result, tuple):
                return 200, result[0], result[1].encode()
            return 200, JSON, _json(result)
        except ApiError as e:
            return e.status, JSON, _json({"error": e.message})
        except KeyError as e:
            return 404, JSON, _json({"error": str(e).strip("'\"")})
        except (ValueError, BackendError) as e:
            return 400, JSON, _json({"error": str(e)})
        except Exception as e:  # never leak a stack trace to a client
            return 500, JSON, _json({"error": f"internal error: {type(e).__name__}"})

    @staticmethod
    def _parse_body(body: bytes) -> dict:
        if not body:
            return {}
        if len(body) > 1_000_000:
            raise ApiError(413, "request body too large")
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            raise ApiError(400, "body must be valid JSON")
        if not isinstance(data, dict):
            raise ApiError(400, "body must be a JSON object")
        return data

    def _require_auth(self, headers: dict) -> None:
        token = self.settings.api_token
        if not token:
            return
        given = headers.get("authorization", "")
        given = given[7:] if given.lower().startswith("bearer ") else given
        if not hmac.compare_digest(given.encode(), token.encode()):
            raise ApiError(401, "missing or invalid bearer token")

    # ----------------------------------------------------------------- routes
    async def _route(self, method: str, path: str, q: dict, data: dict):
        o = self.orch
        if method == "GET":
            if path == "/healthz":
                return {"status": "ok", "tick": o.clock.tick, "backend": o.backend.name}
            if path == "/metrics":
                return "text/plain; version=0.0.4", self.metrics_text()
            if path == "/api/state":
                return o.state()
            if path == "/api/config":
                return o.config()
            if path == "/api/incidents":
                return [o.public_incident(i) for i in sorted(o.incidents.values(), key=lambda i: i["opened_tick"], reverse=True)]
            m = re.fullmatch(r"/api/incidents/([\w-]+)", path)
            if m:
                inc = o.incidents.get(m.group(1))
                if not inc:
                    raise KeyError(f"incident {m.group(1)} not found")
                return o.public_incident(inc)
            m = re.fullmatch(r"/api/incidents/([\w-]+)/postmortem", path)
            if m:
                text = o.postmortem(m.group(1))
                if text is None:
                    raise KeyError("no post-mortem yet: the incident is still open")
                return "text/markdown; charset=utf-8", text
            m = re.fullmatch(r"/api/logs/([\w.-]+)", path)
            if m:
                tail = max(1, min(int(q.get("tail", 40)), 200))
                return await o.backend.logs(m.group(1), tail)
            raise ApiError(404, f"no route for GET {path}")

        if method == "POST":
            if path == "/webhook/alertmanager":
                parsed = parse_alertmanager(data)
                return {"accepted": len(parsed), **o.ingest_external_alerts(parsed)}
            m = re.fullmatch(r"/api/incidents/([\w-]+)/(approve|reject|acknowledge)", path)
            if m:
                iid, verb = m.groups()
                by = str(data.get("by") or "operator")[:40]
                if verb == "acknowledge":
                    return o.acknowledge(iid)
                try:
                    return o.decide(iid, verb == "approve", by, str(data.get("note", ""))[:200])
                except KeyError as e:
                    raise ApiError(409, str(e).strip("'\""))
            if path == "/api/mode":
                o.set_mode(str(data.get("mode", "")))
                return o.config()
            if path == "/api/speed":
                o.set_speed(float(data.get("speed", 1)))
                return o.config()
            if path == "/api/pause":
                o.set_paused(bool(data.get("paused", True)))
                return o.config()
            if path in ("/api/chaos", "/api/chaos/heal", "/api/reset"):
                return self._simulation_only(path, data)
            raise ApiError(404, f"no route for POST {path}")
        raise ApiError(405, f"{method} not allowed")

    def _simulation_only(self, path: str, data: dict):
        o = self.orch
        if not hasattr(o.backend, "inject"):
            raise ApiError(400, "chaos controls only exist in simulation mode")
        if not self.settings.allow_chaos:
            raise ApiError(403, "chaos controls are disabled on this server")
        now = time.monotonic()
        if path == "/api/chaos":
            if now - self._last_chaos < 1.5:
                raise ApiError(429, "slow down: one failure injection every couple of seconds")
            open_n = sum(1 for i in o.incidents.values() if i["status"] != "resolved")
            if open_n >= 4:
                raise ApiError(429, "four incidents are already open; let the agent work or reset the cluster")
            self._last_chaos = now
            res = o.backend.inject(str(data.get("scenario", "")), data.get("target") or None)
            o.emit("chaos", res)
            return res
        if path == "/api/chaos/heal":
            res = o.backend.heal(str(data.get("service", "")))
            o.emit("chaos", {"healed": res["healed"]})
            return res
        if now - self._last_reset < 4:
            raise ApiError(429, "cluster was reset a moment ago")
        self._last_reset = now
        o.reset()
        return {"ok": True}

    # ----------------------------------------------------------------- streaming
    async def stream(self):
        """Server-sent events: one full state, then incremental events."""
        o = self.orch
        if len(o._subs) >= MAX_SSE_CLIENTS:
            raise ApiError(503, "too many live viewers right now")
        q = o.subscribe()
        try:
            yield self._sse("state", o.state())
            while True:
                try:
                    ev = await asyncio.wait_for(q.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                yield self._sse(ev["type"], ev["data"])
        finally:
            o.unsubscribe(q)

    @staticmethod
    def _sse(event: str, data) -> str:
        return f"event: {event}\ndata: {_json(data).decode()}\n\n"

    # ----------------------------------------------------------------- prometheus metrics
    def metrics_text(self) -> str:
        o = self.orch
        by_status: dict[str, int] = {}
        for i in o.incidents.values():
            by_status[i["status"]] = by_status.get(i["status"], 0) + 1
        for a in o.archived:
            if a["id"] not in o.incidents:
                by_status[a["status"]] = by_status.get(a["status"], 0) + 1
        actions: dict[str, int] = {}
        for h in o.policy.history:
            actions[h["type"]] = actions.get(h["type"], 0) + 1
        ttrs = [(i["closed_tick"] - i["opened_tick"]) * o.seconds_per_tick for i in o.incidents.values()
                if i["status"] == "resolved" and i["closed_tick"] is not None]
        lines = ["# HELP vigil_incidents Incidents by status.", "# TYPE vigil_incidents gauge"]
        lines += [f'vigil_incidents{{status="{k}"}} {v}' for k, v in sorted(by_status.items())]
        lines += ["# HELP vigil_actions_total Remediation actions executed.", "# TYPE vigil_actions_total counter"]
        lines += [f'vigil_actions_total{{type="{k}"}} {v}' for k, v in sorted(actions.items())]
        lines += ["# HELP vigil_mean_time_to_recovery_seconds Mean time to recovery of resolved incidents.",
                  "# TYPE vigil_mean_time_to_recovery_seconds gauge",
                  f"vigil_mean_time_to_recovery_seconds {sum(ttrs) / len(ttrs) if ttrs else 0:.1f}",
                  "# HELP vigil_alerts_firing Alerts currently firing.", "# TYPE vigil_alerts_firing gauge",
                  f"vigil_alerts_firing {len(o.alerts.firing)}"]
        return "\n".join(lines) + "\n"
