"""Shared helpers: build an orchestrator over the simulator and drive it tick by tick."""
from __future__ import annotations

import asyncio
import tempfile
from types import SimpleNamespace

from agent.config import Settings, load_spec
from agent.llm import ResilientDiagnoser
from agent.orchestrator import Orchestrator
from agent.simulator import ClusterSimulator


def make(mode="auto", diagnoser=None, seed=7):
    spec = load_spec()
    settings = Settings(mode=mode, data_dir=tempfile.mkdtemp(), seed=seed)
    sim = ClusterSimulator(spec, seed=seed)
    orch = Orchestrator(sim, spec, diagnoser or ResilientDiagnoser(None), settings)
    return orch, sim


async def settle(n=6):
    for _ in range(n):
        await asyncio.sleep(0)


async def run(orch, ticks):
    for _ in range(ticks):
        await orch.tick()
        await settle()


async def warmup(orch, ticks=25):
    await run(orch, ticks)


def only(orch):
    incs = list(orch.incidents.values())
    return incs[0] if incs else None
