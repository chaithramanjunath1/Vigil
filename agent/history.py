"""Rolling metric history. Backend-agnostic: fed one snapshot per tick."""
from __future__ import annotations

from collections import deque

SERVICE_METRICS = ("rps", "p95_ms", "error_rate", "cpu_pct", "mem_pct")
POD_METRICS = ("cpu_pct", "mem_pct")


def slope(values: list[float]) -> float:
    """Least-squares slope per sample. 0.0 when there is too little data."""
    n = len(values)
    if n < 3:
        return 0.0
    mean_x = (n - 1) / 2
    mean_y = sum(values) / n
    num = sum((i - mean_x) * (v - mean_y) for i, v in enumerate(values))
    den = sum((i - mean_x) ** 2 for i in range(n))
    return num / den if den else 0.0


class MetricsHistory:
    BASELINE_SAMPLES = 20

    def __init__(self, maxlen: int = 240) -> None:
        self.maxlen = maxlen
        self.reset()

    def reset(self) -> None:
        self.ticks: deque[int] = deque(maxlen=self.maxlen)
        self.svc: dict[str, dict[str, deque]] = {}
        self.pod: dict[str, dict[str, deque]] = {}
        self._baseline_acc: dict[str, dict[str, list[float]]] = {}
        self.baselines: dict[str, dict[str, float]] = {}
        self.latest: dict | None = None
        self.snapshots: deque[dict] = deque(maxlen=12)

    # ------------------------------------------------------------------ record
    def record(self, snap: dict) -> None:
        self.latest = snap
        self.snapshots.append(snap)
        self.ticks.append(snap["tick"])
        seen_pods: set[str] = set()
        for s in snap["services"]:
            series = self.svc.setdefault(s["name"], {m: deque(maxlen=self.maxlen) for m in SERVICE_METRICS})
            for m in SERVICE_METRICS:
                series[m].append(s[m])
            self._update_baseline(s)
            for p in s["pods"]:
                seen_pods.add(p["name"])
                ps = self.pod.setdefault(p["name"], {m: deque(maxlen=60) for m in POD_METRICS})
                for m in POD_METRICS:
                    ps[m].append(p[m])
        for name in [n for n in self.pod if n not in seen_pods]:
            del self.pod[name]

    def _update_baseline(self, s: dict) -> None:
        name = s["name"]
        if name in self.baselines:
            return
        healthy = s["health"] == "healthy" and s["ready"] == s["desired"]
        if not healthy:
            return
        acc = self._baseline_acc.setdefault(name, {m: [] for m in SERVICE_METRICS})
        for m in SERVICE_METRICS:
            acc[m].append(s[m])
        if len(acc["rps"]) >= self.BASELINE_SAMPLES:
            self.baselines[name] = {m: sum(v) / len(v) for m, v in acc.items()}

    # ------------------------------------------------------------------ queries
    def series(self, service: str, metric: str, n: int | None = None) -> list[float]:
        vals = list(self.svc.get(service, {}).get(metric, []))
        return vals[-n:] if n else vals

    def pod_series(self, pod: str, metric: str, n: int | None = None) -> list[float]:
        vals = list(self.pod.get(pod, {}).get(metric, []))
        return vals[-n:] if n else vals

    def pod_trend(self, pod: str, metric: str = "mem_pct", n: int = 8) -> float:
        return round(slope(self.pod_series(pod, metric, n)), 3)

    def baseline(self, service: str, metric: str) -> float | None:
        return self.baselines.get(service, {}).get(metric)

    def export(self, n: int = 120) -> dict:
        """History for the dashboard sparklines."""
        out: dict = {"ticks": list(self.ticks)[-n:], "services": {}}
        for name, series in self.svc.items():
            out["services"][name] = {m: [round(v, 4) for v in list(series[m])[-n:]] for m in SERVICE_METRICS}
        return out
