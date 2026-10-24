"""Executes an approved action through a backend and verifies the result.

The executor never sees raw model text. It receives a policy-approved action
dict and can only call the three whitelisted backend methods.
"""
from __future__ import annotations

from .backend import BackendError, ClusterBackend


class Executor:
    def __init__(self, backend: ClusterBackend, namespace: str) -> None:
        self.backend = backend
        self.namespace = namespace

    async def run(self, action: dict) -> dict:
        t, target = action["type"], action["target"]
        try:
            if t == "restart_pod":
                res = await self.backend.restart_pod(self.namespace, target)
            elif t == "scale_deployment":
                res = await self.backend.scale_deployment(self.namespace, target, int(action["replicas"]))
            elif t == "rollback_deployment":
                res = await self.backend.rollback_deployment(self.namespace, target)
            else:
                return {"ok": False, "detail": f"executor refuses unsupported action {t!r}"}
        except BackendError as e:
            return {"ok": False, "detail": str(e)}
        except Exception as e:  # real clusters raise many things
            return {"ok": False, "detail": f"{type(e).__name__}: {e}"}
        return {"ok": True, "detail": res.get("detail", "done")}

    @staticmethod
    def command_preview(action: dict, namespace: str) -> str:
        t, target = action["type"], action["target"]
        if t == "restart_pod":
            return f"kubectl delete pod {target} -n {namespace}"
        if t == "scale_deployment":
            return f"kubectl scale deployment/{target} --replicas={action['replicas']} -n {namespace}"
        if t == "rollback_deployment":
            return f"kubectl rollout undo deployment/{target} -n {namespace}"
        return f"# escalate {target}: page the owning team"
