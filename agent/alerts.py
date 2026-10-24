"""Alert rules (Prometheus-style) and Alertmanager webhook helpers.

In simulation mode AlertEngine plays the part of Prometheus + Alertmanager. In a
real cluster the same payload shape arrives over HTTP at /webhook/alertmanager,
so everything downstream of `parse_alertmanager` is identical in both modes.
"""
from __future__ import annotations

from datetime import datetime, timezone

RESOLVE_AFTER = 2  # clear ticks before an alert resolves (hysteresis)


class AlertEngine:
    def __init__(self, spec: dict) -> None:
        self.th = spec["thresholds"]
        self.namespace = spec["namespace"]
        self.reset()

    def reset(self) -> None:
        self.pending: dict[str, int] = {}
        self.clear: dict[str, int] = {}
        self.firing: dict[str, dict] = {}

    # --------------------------------------------------------------- conditions
    def _conditions(self, snap: dict) -> dict[str, dict]:
        th, ft = self.th, self.th["for_ticks"]
        active: dict[str, dict] = {}

        def add(name, service, severity, summary, need, pod=None):
            fp = f"{name}:{service}:{pod or ''}"
            active[fp] = {"fingerprint": fp, "name": name, "service": service, "pod": pod,
                          "severity": severity, "summary": summary, "need": need}

        for s in snap["services"]:
            n = s["name"]
            if s["error_rate"] > th["error_rate"]:
                sev = "critical" if s["error_rate"] > th["error_rate_critical"] else "warning"
                add("HighErrorRate", n, sev,
                    f"{n} error rate {s['error_rate'] * 100:.1f}% (threshold {th['error_rate'] * 100:.0f}%)", ft["error_rate"])
            if s["p95_ms"] > s["slo_ms"]:
                sev = "critical" if s["p95_ms"] > 3 * s["slo_ms"] else "warning"
                add("HighLatencyP95", n, sev,
                    f"{n} p95 latency {s['p95_ms']:.0f}ms (SLO {s['slo_ms']}ms)", ft["latency"])
            if s["cpu_pct"] > th["cpu_pct"]:
                add("HighCPU", n, "warning", f"{n} CPU at {s['cpu_pct']:.0f}% (threshold {th['cpu_pct']}%)", ft["cpu"])
            for p in s["pods"]:
                if p["status"] == "Running" and p["mem_pct"] > th["mem_pct"]:
                    add("HighMemory", n, "warning",
                        f"{p['name']} memory at {p['mem_pct']:.0f}% of its {p['limit_mb']}Mi limit", ft["mem"], p["name"])
                if p["status"] == "OOMKilled":
                    add("PodOOMKilled", n, "warning", f"{p['name']} was OOMKilled (restarts: {p['restarts']})", ft["oom"], p["name"])
                if p["status"] == "CrashLoopBackOff":
                    add("PodCrashLooping", n, "critical",
                        f"{p['name']} is in CrashLoopBackOff (restarts: {p['restarts']})", ft["crashloop"], p["name"])
        return active

    # --------------------------------------------------------------- evaluation
    def evaluate(self, snap: dict) -> tuple[list[dict], list[dict]]:
        """Return (newly_firing, newly_resolved) for this snapshot."""
        active = self._conditions(snap)
        fired: list[dict] = []
        resolved: list[dict] = []

        for fp, a in active.items():
            self.clear.pop(fp, None)
            if fp in self.firing:
                self.firing[fp]["summary"] = a["summary"]
                self.firing[fp]["severity"] = a["severity"]
                continue
            self.pending[fp] = self.pending.get(fp, 0) + 1
            if self.pending[fp] >= a["need"]:
                alert = {k: v for k, v in a.items() if k != "need"}
                alert.update({"status": "firing", "tick": snap["tick"]})
                self.firing[fp] = alert
                fired.append(dict(alert))
        for fp in [f for f in self.pending if f not in active]:
            del self.pending[fp]
        for fp in list(self.firing):
            if fp in active:
                continue
            self.clear[fp] = self.clear.get(fp, 0) + 1
            if self.clear[fp] >= RESOLVE_AFTER:
                alert = self.firing.pop(fp)
                self.clear.pop(fp, None)
                alert = dict(alert, status="resolved", resolved_tick=snap["tick"])
                resolved.append(alert)
        return fired, resolved

    def firing_list(self) -> list[dict]:
        return [dict(a) for a in self.firing.values()]


# ------------------------------------------------------------------ webhooks
def _iso(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts if ts is not None else datetime.now().timestamp(), tz=timezone.utc).isoformat()


def to_alertmanager(alerts: list[dict], namespace: str, status: str = "firing") -> dict:
    """Wrap alerts in the Alertmanager v4 webhook payload."""
    return {
        "version": "4",
        "groupKey": "{}:{alertname}",
        "status": status,
        "receiver": "vigil",
        "externalURL": "http://alertmanager.local",
        "alerts": [
            {
                "status": a["status"],
                "labels": {k: v for k, v in {
                    "alertname": a["name"], "service": a["service"], "pod": a.get("pod"),
                    "severity": a["severity"], "namespace": namespace}.items() if v},
                "annotations": {"summary": a["summary"]},
                "startsAt": _iso(),
                "fingerprint": a["fingerprint"],
            }
            for a in alerts
        ],
    }


def _service_from_labels(labels: dict) -> str | None:
    for key in ("service", "deployment", "app", "app_kubernetes_io_name", "job"):
        if labels.get(key):
            return str(labels[key])
    pod = labels.get("pod")
    if pod and pod.count("-") >= 2:
        return pod.rsplit("-", 2)[0]
    return None


def parse_alertmanager(payload: dict) -> list[dict]:
    """Normalise an Alertmanager webhook body into Vigil alert dicts."""
    out: list[dict] = []
    for raw in payload.get("alerts", []) or []:
        labels = raw.get("labels", {}) or {}
        service = _service_from_labels(labels)
        if not service:
            continue
        name = labels.get("alertname", "UnknownAlert")
        pod = labels.get("pod")
        ann = raw.get("annotations", {}) or {}
        out.append({
            "fingerprint": raw.get("fingerprint") or f"{name}:{service}:{pod or ''}",
            "name": name,
            "service": service,
            "pod": pod,
            "severity": labels.get("severity", "warning"),
            "summary": ann.get("summary") or ann.get("description") or name,
            "status": raw.get("status", payload.get("status", "firing")),
            "namespace": labels.get("namespace"),
        })
    return out
