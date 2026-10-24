"""The agent loop: detect -> diagnose -> check guardrails -> (approve) -> act -> verify -> report.

One Orchestrator owns a backend, the alert engine, the policy engine, the LLM
diagnoser and the incident store. It is transport-agnostic: the HTTP layer only
calls the public methods below and subscribes to `events`.
"""
from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from pathlib import Path

from .alerts import AlertEngine
from .backend import BackendError, ClusterBackend
from .context import build_context, select_services
from .executor import Executor
from .history import MetricsHistory
from .llm import ResilientDiagnoser
from .policy import Decision, PolicyEngine
from .postmortem import build_postmortem

OPEN = ("detecting", "diagnosing", "awaiting_approval", "executing", "verifying", "escalated")


class Orchestrator:
    def __init__(self, backend: ClusterBackend, spec: dict, diagnoser: ResilientDiagnoser, settings) -> None:
        self.backend = backend
        self.spec = spec
        self.settings = settings
        self.namespace = spec["namespace"]
        self.clock = backend.clock
        self.diagnoser = diagnoser
        self.history = MetricsHistory()
        self.alerts = AlertEngine(spec)
        self.policy = PolicyEngine(spec, mode=settings.mode)
        self.executor = Executor(backend, self.namespace)
        self.graph = {s["name"]: s["calls"] for s in spec["services"]}
        self.seconds_per_tick = 1.0 if backend.name == "simulation" else settings.poll_seconds

        self.incidents: dict[str, dict] = {}
        self.archived: list[dict] = []
        self._seq = 0
        self._tasks: dict[str, asyncio.Task] = {}
        self._approvals: dict[str, asyncio.Future] = {}
        self._subs: set[asyncio.Queue] = set()
        self.paused = False
        self.speed = settings.speed
        self.last_snapshot: dict | None = None
        self._runner: asyncio.Task | None = None
        self._store = Path(settings.data_dir) / "incidents.jsonl"
        self._load_archive()

    # ================================================================== events
    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=400)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)

    def emit(self, kind: str, data: dict) -> None:
        for q in list(self._subs):
            try:
                q.put_nowait({"type": kind, "data": data})
            except asyncio.QueueFull:
                self._subs.discard(q)  # slow client: drop it, it will reconnect and resync

    # ================================================================== run loop
    async def start(self) -> None:
        if self._runner is None or self._runner.done():
            self._runner = asyncio.create_task(self._run(), name="vigil-loop")

    async def stop(self) -> None:
        if self._runner:
            self._runner.cancel()
            try:
                await self._runner
            except (asyncio.CancelledError, Exception):
                pass
        for t in list(self._tasks.values()):
            t.cancel()

    async def _run(self) -> None:
        while True:
            if not self.paused:
                try:
                    await self.tick()
                except asyncio.CancelledError:
                    raise
                except Exception as e:  # keep the loop alive; surface the problem
                    self.emit("error", {"message": f"tick failed: {type(e).__name__}: {e}"})
            await asyncio.sleep(max(0.02, self.settings.tick_seconds / max(self.speed, 0.1)))

    async def tick(self) -> dict:
        snap = await self.backend.advance()
        self.history.record(snap)
        self.last_snapshot = snap
        self.clock.notify()
        fired, resolved = self.alerts.evaluate(snap)
        for a in fired:
            self._on_alert_fired(a, snap)
        for a in resolved:
            self._on_alert_resolved(a)
        self.emit("tick", {
            "tick": snap["tick"], "services": snap["services"],
            "alerts": self.alerts.firing_list(),
        })
        return snap

    # ================================================================== alerts -> incidents
    def ingest_external_alerts(self, parsed: list[dict]) -> dict:
        """Alertmanager webhook entry point (real clusters)."""
        snap = self.last_snapshot or {"tick": self.clock.tick, "services": []}
        fired = resolved = 0
        for a in parsed:
            if a["service"] not in self.graph:
                continue
            if a["status"] == "resolved":
                self.alerts.firing.pop(a["fingerprint"], None)
                self._on_alert_resolved(dict(a, resolved_tick=self.clock.tick))
                resolved += 1
            else:
                a = dict(a, tick=self.clock.tick)
                if a["fingerprint"] not in self.alerts.firing:
                    self.alerts.firing[a["fingerprint"]] = a
                    self._on_alert_fired(a, snap)
                    fired += 1
        return {"fired": fired, "resolved": resolved}

    def _related(self, a: str, b: str) -> bool:
        return a == b or any(c["to"] == b for c in self.graph.get(a, [])) or any(c["to"] == a for c in self.graph.get(b, []))

    def _find_incident(self, alert: dict) -> dict | None:
        svc = alert["service"]
        for inc in self.incidents.values():
            if inc["status"] not in OPEN:
                continue
            if svc in inc["services"]:
                return inc
            if inc["status"] == "detecting":
                return inc
            if any(self._related(svc, s) for s in inc["services"]) and inc["status"] != "escalated":
                return inc
        return None

    def _on_alert_fired(self, alert: dict, snap: dict) -> None:
        inc = self._find_incident(alert)
        if inc is None:
            inc = self._new_incident(alert)
        if alert["service"] not in inc["services"]:
            inc["services"].append(alert["service"])
        inc["alerts"].append({**alert, "status": "firing"})
        if alert["severity"] == "critical":
            inc["severity"] = "critical"
        self._log(inc, "alert", f"{alert['name']} firing on {alert['service']}", alert["summary"])
        self._publish(inc)

    def _on_alert_resolved(self, alert: dict) -> None:
        for inc in self.incidents.values():
            for a in inc["alerts"]:
                if a["fingerprint"] == alert["fingerprint"] and a["status"] == "firing":
                    a["status"] = "resolved"
        self.emit("alert_resolved", {"fingerprint": alert["fingerprint"]})

    def _new_incident(self, alert: dict) -> dict:
        self._seq += 1
        iid = f"INC-{self._seq:04d}"
        inc = {
            "id": iid, "title": f"{alert['name']} on {alert['service']}", "status": "detecting",
            "severity": alert["severity"], "opened_tick": self.clock.tick, "opened_at": time.time(),
            "closed_tick": None, "diagnosed_tick": None, "services": [alert["service"]],
            "culprit_service": None, "alerts": [], "timeline": [], "diagnosis": None, "decision": None,
            "action": None, "verification": None, "security": [], "resolved_by": None,
            "approval": None, "postmortem": None, "seconds_per_tick": self.seconds_per_tick,
        }
        self.incidents[iid] = inc
        self._tasks[iid] = asyncio.create_task(self._handle(iid), name=iid)
        return inc

    # ================================================================== bookkeeping
    def _log(self, inc: dict, kind: str, title: str, detail: str = "") -> None:
        inc["timeline"].append({"tick": self.clock.tick, "kind": kind, "title": title, "detail": detail})

    def _set(self, inc: dict, status: str) -> None:
        inc["status"] = status
        self._publish(inc)

    def _publish(self, inc: dict) -> None:
        self.emit("incident", self.public_incident(inc))

    def public_incident(self, inc: dict) -> dict:
        return {k: v for k, v in inc.items() if k != "postmortem"} | {"has_postmortem": bool(inc.get("postmortem"))}

    def _recent_actions(self, services: list[str], tick: int) -> list[dict]:
        out: list[dict] = []
        for s in services:
            out += self.policy.recent(s, tick)
        return out

    # ================================================================== incident lifecycle
    async def _handle(self, iid: str) -> None:
        inc = self.incidents[iid]
        try:
            await self.clock.wait_ticks(self.spec["policy"]["debounce_ticks"])
            await self._diagnose_and_act(inc)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self._log(inc, "error", "Agent error", f"{type(e).__name__}: {e}")
            self._escalate(inc, f"The agent hit an internal error: {e}")
        finally:
            self._tasks.pop(iid, None)

    async def _gather_context(self, inc: dict) -> tuple[dict, list[dict]]:
        snap = self.last_snapshot or await self.backend.snapshot()
        firing = self.alerts.firing_list()
        scope = select_services(snap, firing, self.graph)
        logs = {n: await self.backend.logs(n, 40) for n in scope}
        deployments = await self.backend.deployments()
        prior = self._recent_actions(scope, snap["tick"])
        return build_context(snap, self.history, firing, logs, deployments, prior, self.spec)

    async def _diagnose_and_act(self, inc: dict) -> None:
        self._set(inc, "diagnosing")
        ctx, flagged = await self._gather_context(inc)
        n_svc, n_logs = len(ctx["services"]), sum(len(v) for v in ctx["logs"].values())
        self._log(inc, "context", "Gathered evidence",
                  f"{len(ctx['alerts'])} alerts, {n_svc} services in scope, {n_logs} log lines, rollout history")
        if flagged:
            inc["security"] = [{"tick": ln["tick"], "pod": ln["pod"], "msg": ln["msg"]} for ln in flagged]
            self._log(inc, "security", "Quarantined suspicious log content",
                      f"{len(flagged)} log line(s) tried to instruct the agent and were removed before diagnosis")
        self._publish(inc)

        diagnosis = await self.diagnoser.diagnose(ctx)
        inc["diagnosis"] = diagnosis
        inc["diagnosed_tick"] = self.clock.tick
        inc["culprit_service"] = diagnosis.get("culprit_service")
        if inc["culprit_service"] and inc["culprit_service"] not in inc["services"]:
            inc["services"].append(inc["culprit_service"])
        if diagnosis.get("culprit_service"):
            inc["title"] = f"{diagnosis['culprit_service']}: {diagnosis['root_cause'].split(':')[0].rstrip('.')}"[:90]
        engine = diagnosis["engine"] + (" (fallback)" if diagnosis["fallback"] else "")
        self._log(inc, "diagnosis", f"Diagnosed by {engine}",
                  f"{diagnosis['root_cause']} Confidence {int(diagnosis['confidence'] * 100)}%.")
        if diagnosis["fallback"]:
            self._log(inc, "note", "LLM unavailable, used offline reasoner", diagnosis.get("degraded_reason") or "")
        self._publish(inc)

        snap = self.last_snapshot
        decision = self.policy.evaluate(diagnosis, snap, snap["tick"], quarantined=len(flagged))
        inc["decision"] = decision.as_dict()
        action = decision.action or diagnosis["action"]
        inc["proposed"] = {**diagnosis["action"], "command": Executor.command_preview(diagnosis["action"], self.namespace)}
        failed = [c for c in decision.checks if not c.passed]
        self._log(inc, "policy", f"Guardrails: {decision.verdict}",
                  decision.reason + (f" Failed: {', '.join(c.name for c in failed)}." if failed else ""))
        self._publish(inc)

        if decision.verdict == "deny":
            self._escalate(inc, decision.reason)
            await self._await_recovery(inc, window=None)
            return
        if action["type"] == "escalate":
            self._escalate(inc, action.get("rationale") or "No safe automated action exists.")
            await self._await_recovery(inc, window=None)
            return
        if decision.verdict == "approve":
            ok = await self._wait_for_approval(inc, decision)
            if not ok:
                await self._await_recovery(inc, window=None)
                return
            snap = self.last_snapshot
            decision = self.policy.evaluate(diagnosis, snap, snap["tick"], human_approved=True)
            inc["decision"] = decision.as_dict()
            self._log(inc, "policy", f"Guardrails re-checked: {decision.verdict}", decision.reason)
            if decision.verdict != "allow":
                self._escalate(inc, decision.reason)
                await self._await_recovery(inc, window=None)
                return
            action = decision.action
        await self._execute_and_verify(inc, action, human=inc["approval"] is not None)

    # ---------------------------------------------------------------- approval
    async def _wait_for_approval(self, inc: dict, decision: Decision) -> bool:
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._approvals[inc["id"]] = fut
        act = inc["proposed"]
        inc["approval"] = None
        inc["pending_approval"] = {"command": act["command"], "reason": decision.reason,
                                   "deadline_tick": self.clock.tick + self.spec["policy"]["approval_timeout_ticks"]}
        self._log(inc, "approval", "Waiting for human approval", f"`{act['command']}`")
        self._set(inc, "awaiting_approval")
        timeout = asyncio.create_task(self.clock.wait_ticks(self.spec["policy"]["approval_timeout_ticks"]))
        try:
            done, _ = await asyncio.wait({fut, timeout}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            timeout.cancel()
            self._approvals.pop(inc["id"], None)
        inc.pop("pending_approval", None)
        if fut in done and fut.result()["approved"]:
            inc["approval"] = {"by": fut.result()["by"], "tick": self.clock.tick}
            self._log(inc, "approval", f"Approved by {fut.result()['by']}", "")
            return True
        if fut in done:
            self._log(inc, "approval", f"Rejected by {fut.result()['by']}", fut.result().get("note", ""))
            self._escalate(inc, "A human rejected the proposed action.")
        else:
            self._log(inc, "approval", "Approval timed out", "")
            self._escalate(inc, "Nobody approved the action in time, so it was not run.")
        return False

    def decide(self, iid: str, approved: bool, by: str = "operator", note: str = "") -> dict:
        fut = self._approvals.get(iid)
        if fut is None or fut.done():
            raise KeyError(f"{iid} is not waiting for approval")
        fut.set_result({"approved": approved, "by": by, "note": note})
        return {"ok": True}

    # ---------------------------------------------------------------- act + verify
    async def _execute_and_verify(self, inc: dict, action: dict, human: bool) -> None:
        self._set(inc, "executing")
        command = Executor.command_preview(action, self.namespace)
        self._log(inc, "action", "Executing", f"`{command}`")
        res = await self.executor.run(action)
        service, _ = PolicyEngine.owner_of(action["target"], self.last_snapshot)
        inc["action"] = {"type": action["type"], "target": action["target"], "replicas": action.get("replicas"),
                         "command": command, "ok": res["ok"], "result": res["detail"], "tick": self.clock.tick,
                         "by": "human-approved agent" if human else "agent"}
        if not res["ok"]:
            self._log(inc, "action", "Action failed", res["detail"])
            self._escalate(inc, f"The action failed: {res['detail']}")
            await self._await_recovery(inc, window=None)
            return
        self.policy.record(self.clock.tick, service or action["target"], action["type"])
        self._log(inc, "action", "Action applied", res["detail"])
        self._set(inc, "verifying")
        await self._await_recovery(inc, window=self.spec["policy"]["verify_window_ticks"])

    def _escalate(self, inc: dict, reason: str) -> None:
        inc["escalation"] = {"reason": reason, "tick": self.clock.tick}
        self._log(inc, "escalate", "Handed to a human", reason)
        self._set(inc, "escalated")

    async def _await_recovery(self, inc: dict, window: int | None) -> None:
        need = self.spec["policy"]["verify_healthy_ticks"]
        start, streak = self.clock.tick, 0
        while True:
            await self.clock.wait_ticks(1)
            if inc["status"] not in OPEN:
                return
            snap = self.last_snapshot
            by = {s["name"]: s for s in snap["services"]}
            watch = set(inc["services"]) & set(by)
            healthy = all(by[n]["health"] == "healthy" for n in watch)
            quiet = not any(a["service"] in watch for a in self.alerts.firing.values())
            streak = streak + 1 if (healthy and quiet) else 0
            if streak >= need:
                self._resolve(inc, "agent" if inc["status"] == "verifying" else "human or self-healed", start)
                return
            if window is not None and self.clock.tick - start >= window:
                inc["verification"] = {"ok": False, "detail": f"Services were still unhealthy {window} ticks after the action."}
                self._log(inc, "verify", "Fix did not hold", inc["verification"]["detail"])
                self._escalate(inc, "The automated fix did not restore health. A human needs to take over.")
                window = None

    def _resolve(self, inc: dict, by: str, start_tick: int) -> None:
        watch = ", ".join(sorted(inc["services"]))
        inc["verification"] = {"ok": True, "detail": f"{watch} healthy and quiet for {self.spec['policy']['verify_healthy_ticks']} consecutive checks."}
        inc["resolved_by"] = by
        inc["closed_tick"] = self.clock.tick
        self._log(inc, "verify", "Recovery verified", inc["verification"]["detail"])
        self._log(inc, "resolved", "Incident resolved", f"Time to recovery {self.clock.tick - inc['opened_tick']} ticks")
        inc["status"] = "resolved"  # set first so the post-mortem records the final status
        inc["postmortem"] = build_postmortem(inc, self.seconds_per_tick)
        self._set(inc, "resolved")
        self._archive(inc)

    # ================================================================== operator controls
    def acknowledge(self, iid: str) -> dict:
        inc = self.incidents.get(iid)
        if not inc or inc["status"] != "escalated":
            raise KeyError(f"{iid} is not an escalated incident")
        inc["resolved_by"] = "human"
        inc["closed_tick"] = self.clock.tick
        self._log(inc, "resolved", "Closed by a human", "")
        inc["verification"] = inc["verification"] or {"ok": True, "detail": "Closed manually by an operator."}
        inc["status"] = "resolved"
        inc["postmortem"] = build_postmortem(inc, self.seconds_per_tick)
        self._set(inc, "resolved")
        self._archive(inc)
        return {"ok": True}

    def set_mode(self, mode: str) -> None:
        if mode not in ("observe", "approve", "auto"):
            raise ValueError("mode must be observe, approve or auto")
        self.policy.mode = mode
        self.settings.mode = mode
        self.emit("config", self.config())

    def set_speed(self, speed: float) -> None:
        self.speed = max(0.25, min(float(speed), 20.0))
        self.emit("config", self.config())

    def set_paused(self, paused: bool) -> None:
        self.paused = bool(paused)
        self.emit("config", self.config())

    def reset(self) -> None:
        """Simulation only: back to a clean cluster."""
        for t in list(self._tasks.values()):
            t.cancel()
        self._tasks.clear()
        for f in self._approvals.values():
            if not f.done():
                f.cancel()
        self._approvals.clear()
        if hasattr(self.backend, "reset"):
            self.backend.reset()
        self.history.reset()
        self.alerts.reset()
        self.policy.reset()
        self.incidents.clear()
        self.last_snapshot = None
        self._seq = 0
        self.emit("reset", {})

    # ================================================================== views
    def config(self) -> dict:
        return {
            "mode": self.policy.mode, "speed": self.speed, "paused": self.paused,
            "backend": self.backend.name, "engine": self.diagnoser.label, "engine_is_llm": self.diagnoser.is_llm,
            "namespace": self.namespace, "seconds_per_tick": self.seconds_per_tick,
            "chaos_enabled": bool(getattr(self.settings, "allow_chaos", True)) and hasattr(self.backend, "inject"),
            "policy": self.spec["policy"],
        }

    def state(self) -> dict:
        snap = self.last_snapshot or {"tick": self.clock.tick, "services": [], "edges": []}
        incs = sorted(self.incidents.values(), key=lambda i: i["opened_tick"], reverse=True)
        return {
            "config": self.config(), "snapshot": snap, "alerts": self.alerts.firing_list(),
            "history": self.history.export(), "incidents": [self.public_incident(i) for i in incs],
            "archive": self.archived[-20:], "scenarios": self.spec["scenarios"],
        }

    def postmortem(self, iid: str) -> str | None:
        inc = self.incidents.get(iid) or next((a for a in self.archived if a["id"] == iid), None)
        return (inc or {}).get("postmortem")

    # ================================================================== persistence
    def _archive(self, inc: dict) -> None:
        row = {k: inc[k] for k in ("id", "title", "status", "severity", "opened_tick", "closed_tick", "culprit_service",
                                   "resolved_by", "seconds_per_tick") if k in inc}
        row["action"] = (inc.get("action") or {}).get("command")
        row["engine"] = (inc.get("diagnosis") or {}).get("engine")
        row["postmortem"] = inc.get("postmortem")
        row["ts"] = time.time()
        self.archived.append(row)
        try:
            self._store.parent.mkdir(parents=True, exist_ok=True)
            with self._store.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row) + "\n")
        except OSError:
            pass  # read-only filesystem (e.g. some hosts): in-memory archive still works

    def _load_archive(self) -> None:
        try:
            lines = self._store.read_text(encoding="utf-8").splitlines()[-50:]
        except OSError:
            return
        for ln in lines:
            try:
                self.archived.append(json.loads(ln))
            except json.JSONDecodeError:
                continue
