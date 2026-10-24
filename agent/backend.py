"""The contract between the agent and a cluster (simulated or real)."""
from __future__ import annotations

from abc import ABC, abstractmethod

from .clock import Clock


class BackendError(RuntimeError):
    """Raised when a cluster operation cannot be completed."""


def classify_health(s: dict) -> str:
    """healthy | degraded | critical, from one service's metrics."""
    slo = s.get("slo_ms") or 1e9
    if s["ready"] == 0 or s["error_rate"] > 0.25 or s["p95_ms"] > 3 * slo:
        return "critical"
    bad_pod = any(p["status"] in ("CrashLoopBackOff", "OOMKilled", "Error") or p["mem_pct"] > 75 for p in s["pods"])
    if (
        s["error_rate"] > 0.05
        or s["p95_ms"] > slo
        or s["cpu_pct"] > 90
        or bad_pod
        or s["ready"] < s["desired"] and not all(p["status"] == "Pending" for p in s["pods"] if not p["ready"])
    ):
        return "degraded"
    return "healthy"


class ClusterBackend(ABC):
    name = "backend"
    clock: Clock

    @abstractmethod
    async def advance(self) -> dict:
        """Wait for / produce the next sample and return its snapshot.
        The caller records it and then calls clock.notify()."""

    @abstractmethod
    async def snapshot(self) -> dict:
        """Current state: {"tick", "services": [...], "edges": [...]}."""

    @abstractmethod
    async def logs(self, service: str, tail: int = 20) -> list[dict]:
        """Recent log lines: [{"tick", "pod", "level", "msg"}]."""

    @abstractmethod
    async def deployments(self) -> dict[str, list[dict]]:
        """Revision history per deployment: {svc: [{"revision","version","tick","note"}]}."""

    @abstractmethod
    async def restart_pod(self, namespace: str, pod: str) -> dict: ...

    @abstractmethod
    async def scale_deployment(self, namespace: str, deployment: str, replicas: int) -> dict: ...

    @abstractmethod
    async def rollback_deployment(self, namespace: str, deployment: str) -> dict: ...
