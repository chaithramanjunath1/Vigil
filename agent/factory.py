"""Wires settings into a ready-to-run Orchestrator."""
from __future__ import annotations

import asyncio
import random

from .config import Settings, load_spec
from .llm import make_diagnoser
from .orchestrator import Orchestrator
from .simulator import ClusterSimulator


def build_orchestrator(settings: Settings) -> Orchestrator:
    spec = load_spec()
    spec["namespace"] = settings.namespace if settings.backend == "kubernetes" else spec["namespace"]
    if settings.backend == "kubernetes":
        from .k8s_backend import KubernetesBackend  # imported lazily: only needed on a real cluster
        backend = KubernetesBackend(spec, settings)
    else:
        backend = ClusterSimulator(spec, seed=settings.seed)
    return Orchestrator(backend, spec, make_diagnoser(settings), settings)


async def autopilot(orch: Orchestrator, first_delay: float = 6.0, every: float = 40.0) -> None:
    """Keeps a public demo alive: injects a random failure whenever the cluster is calm."""
    rng = random.Random()
    pool = [s["id"] for s in orch.spec["scenarios"]]
    await asyncio.sleep(first_delay)
    while True:
        calm = not any(i["status"] != "resolved" for i in orch.incidents.values())
        if calm and not orch.paused and orch.last_snapshot and orch.history.baselines:
            res = orch.backend.inject(rng.choice(pool))
            orch.emit("chaos", {**res, "auto": True})
            await asyncio.sleep(every)
        else:
            await asyncio.sleep(5)
