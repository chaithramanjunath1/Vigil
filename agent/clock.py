"""A tick-based clock shared by every backend.

The agent reasons in ticks (one tick = one metrics sample) instead of wall-clock
seconds. That keeps the orchestrator identical across the simulator (fast,
deterministic, drivable from tests) and a real cluster (one tick per scrape).
"""
from __future__ import annotations

import asyncio


class Clock:
    def __init__(self) -> None:
        self.tick = 0
        self._waiters: list[tuple[int, asyncio.Future]] = []

    def bump(self) -> int:
        """Move time forward one tick without waking waiters."""
        self.tick += 1
        return self.tick

    def advance(self) -> int:
        """Move time forward one tick and wake anything waiting for it."""
        self.bump()
        self.notify()
        return self.tick

    def notify(self) -> None:
        """Wake waiters whose tick has arrived. Called after the new sample is recorded."""
        pending: list[tuple[int, asyncio.Future]] = []
        for target, fut in self._waiters:
            if target <= self.tick:
                if not fut.done():
                    fut.set_result(None)
            else:
                pending.append((target, fut))
        self._waiters = pending

    async def wait_until_tick(self, target: int) -> None:
        if self.tick >= target:
            return
        fut = asyncio.get_running_loop().create_future()
        self._waiters.append((target, fut))
        await fut

    async def wait_ticks(self, n: int) -> None:
        await self.wait_until_tick(self.tick + n)

    def reset(self) -> None:
        """Cancel waiters (used when the simulated cluster is reset)."""
        for _, fut in self._waiters:
            if not fut.done():
                fut.cancel()
        self._waiters = []
        self.tick = 0
