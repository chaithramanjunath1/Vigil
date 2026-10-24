"""Real-cluster backend: Kubernetes REST API + Prometheus HTTP API, stdlib only.

Reads state from the API server and Prometheus and applies the three whitelisted
remediations. Auth is the pod's own service account (see deploy/k8s/rbac.yaml),
so the agent can do nothing the Role does not grant, even if this code were
compromised. Outside a cluster, point KUBE_API_URL at `kubectl proxy`.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .backend import BackendError, ClusterBackend, classify_health
from .clock import Clock

SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")
PRUNE = ("pod-template-hash",)


def parse_quantity(q: str | None, default: float = 0.0) -> float:
    """'500m' -> 0.5, '512Mi' -> 536870912, '1' -> 1.0"""
    if not q:
        return default
    m = re.fullmatch(r"([0-9.]+)([a-zA-Z]*)", str(q).strip())
    if not m:
        return default
    n, unit = float(m.group(1)), m.group(2)
    mult = {"": 1, "m": 1e-3, "k": 1e3, "K": 1e3, "M": 1e6, "G": 1e9, "Ki": 1024, "Mi": 1024 ** 2, "Gi": 1024 ** 3}
    return n * mult.get(unit, 1)


class KubernetesBackend(ClusterBackend):
    name = "kubernetes"

    def __init__(self, spec: dict, settings, http=None) -> None:
        self.spec, self.settings = spec, settings
        self.namespace = settings.namespace
        self.clock = Clock()
        self.services = {s["name"]: s for s in spec["services"]}
        self.poll = settings.poll_seconds
        self.prom_url = settings.prometheus_url.rstrip("/")
        self._http = http or self._real_http
        self._last: dict | None = None
        self._ctx = None
        self.api = os.environ.get("KUBE_API_URL", "").rstrip("/")
        self.token = os.environ.get("KUBE_TOKEN", "")
        if not self.api:
            host, port = os.environ.get("KUBERNETES_SERVICE_HOST"), os.environ.get("KUBERNETES_SERVICE_PORT", "443")
            if host:
                self.api = f"https://{host}:{port}"
                if (SA_DIR / "token").exists():
                    self.token = (SA_DIR / "token").read_text().strip()
                if (SA_DIR / "ca.crt").exists():
                    self._ctx = ssl.create_default_context(cafile=str(SA_DIR / "ca.crt"))

    # ------------------------------------------------------------------ http
    def _real_http(self, method: str, url: str, body: dict | None = None, content_type: str = "application/json"):
        headers = {"Accept": "application/json"}
        if self.token and url.startswith(self.api):
            headers["Authorization"] = f"Bearer {self.token}"
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = content_type
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15, context=self._ctx if url.startswith(self.api) else None) as r:
                raw = r.read().decode()
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:200]
            raise BackendError(f"{method} {urllib.parse.urlsplit(url).path} -> HTTP {e.code}: {detail}") from e
        except (urllib.error.URLError, OSError) as e:
            raise BackendError(f"cannot reach {urllib.parse.urlsplit(url).netloc}: {e}") from e
        ctype = "json" if raw[:1] in "{[" else "text"
        return json.loads(raw) if ctype == "json" else raw

    async def _k8s(self, method: str, path: str, body: dict | None = None, content_type: str = "application/json"):
        if not self.api:
            raise BackendError("no Kubernetes API configured: run in-cluster or set KUBE_API_URL (e.g. kubectl proxy)")
        return await asyncio.to_thread(self._http, method, self.api + path, body, content_type)

    async def _prom(self, query: str) -> list[dict]:
        url = f"{self.prom_url}/api/v1/query?" + urllib.parse.urlencode({"query": query})
        try:
            res = await asyncio.to_thread(self._http, "GET", url, None, "application/json")
        except BackendError:
            return []  # Prometheus being down must not stop the agent from seeing pods
        if not isinstance(res, dict) or res.get("status") != "success":
            return []
        return res.get("data", {}).get("result", [])

    # ------------------------------------------------------------------ sampling
    async def advance(self) -> dict:
        await asyncio.sleep(self.poll)
        self.clock.bump()
        self._last = await self._build_snapshot()
        return self._last

    async def snapshot(self) -> dict:
        if self._last is None:
            self._last = await self._build_snapshot()
        return self._last

    async def _build_snapshot(self) -> dict:
        ns = self.namespace
        pods_raw, deps_raw = await asyncio.gather(
            self._k8s("GET", f"/api/v1/namespaces/{ns}/pods"),
            self._k8s("GET", f"/apis/apps/v1/namespaces/{ns}/deployments"))
        q = f'namespace="{ns}"'
        rps, err, p95, pcpu, pmem = await asyncio.gather(
            self._prom(f'sum by (service)(rate(http_requests_total{{{q}}}[1m]))'),
            self._prom(f'sum by (service)(rate(http_requests_total{{{q},status=~"5.."}}[1m])) / sum by (service)(rate(http_requests_total{{{q}}}[1m]))'),
            self._prom(f'histogram_quantile(0.95, sum by (service, le)(rate(http_request_duration_seconds_bucket{{{q}}}[1m]))) * 1000'),
            self._prom(f'sum by (pod)(rate(container_cpu_usage_seconds_total{{{q},container!=""}}[1m]))'),
            self._prom(f'sum by (pod)(container_memory_working_set_bytes{{{q},container!=""}})'))

        def by(res, key):
            out = {}
            for r in res:
                try:
                    v = float(r["value"][1])
                except (KeyError, ValueError, IndexError, TypeError):
                    continue
                if v == v:  # drop NaN (no traffic)
                    out[r["metric"].get(key, "")] = v
            return out
        rps, err, p95, pcpu, pmem = by(rps, "service"), by(err, "service"), by(p95, "service"), by(pcpu, "pod"), by(pmem, "pod")

        deps = {d["metadata"]["name"]: d for d in deps_raw.get("items", [])}
        services = []
        for name, sspec in self.services.items():
            dep = deps.get(name)
            if dep is None:
                continue
            sel = dep["spec"].get("selector", {}).get("matchLabels", {})
            pods = []
            for p in pods_raw.get("items", []):
                labels = p["metadata"].get("labels", {})
                if all(labels.get(k) == v for k, v in sel.items()):
                    pods.append(self._pod_view(p, sspec, pcpu, pmem))
            ready = sum(1 for p in pods if p["ready"])
            n = max(len(pods), 1)
            entry = {
                "name": name, "desired": dep["spec"].get("replicas", 1), "ready": ready,
                "rps": round(rps.get(name, 0.0), 1), "p95_ms": round(p95.get(name, 0.0), 1),
                "error_rate": round(err.get(name, 0.0), 4),
                "cpu_pct": round(sum(p["cpu_pct"] for p in pods) / n, 1),
                "mem_pct": round(sum(p["mem_pct"] for p in pods) / n, 1),
                "revision": int(dep["metadata"].get("annotations", {}).get("deployment.kubernetes.io/revision", 1)),
                "version": self._image_tag(dep["spec"]["template"]),
                "slo_ms": sspec["slo_ms"], "pods": pods,
            }
            entry["health"] = classify_health(entry)
            services.append(entry)
        edges = [{"from": s["name"], "to": c["to"], "critical": c["critical"]} for s in self.spec["services"] for c in s["calls"]]
        return {"tick": self.clock.tick, "services": services, "edges": edges}

    @staticmethod
    def _image_tag(template: dict) -> str:
        image = (template.get("spec", {}).get("containers") or [{}])[0].get("image", "")
        return image.rsplit(":", 1)[1] if ":" in image.rsplit("/", 1)[-1] else "latest"

    def _pod_view(self, p: dict, sspec: dict, pcpu: dict, pmem: dict) -> dict:
        name = p["metadata"]["name"]
        status = p.get("status", {})
        phase = status.get("phase", "Unknown")
        shown, restarts = phase, 0
        for cs in status.get("containerStatuses", []) or []:
            restarts += cs.get("restartCount", 0)
            waiting = (cs.get("state") or {}).get("waiting") or {}
            last = (cs.get("lastState") or {}).get("terminated") or {}
            if waiting.get("reason") in ("CrashLoopBackOff", "Error", "ImagePullBackOff", "ErrImagePull", "CreateContainerConfigError"):
                shown = "CrashLoopBackOff" if waiting["reason"] == "CrashLoopBackOff" else "Error"
            elif last.get("reason") == "OOMKilled" and not cs.get("ready"):
                shown = "OOMKilled"
            elif phase == "Pending":
                shown = "Pending"
        ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in status.get("conditions", []) or [])
        container = (p["spec"].get("containers") or [{}])[0]
        limits = (container.get("resources") or {}).get("limits", {})
        mem_limit = parse_quantity(limits.get("memory"), sspec["mem_limit_mb"] * 1024 ** 2)
        cpu_limit = parse_quantity(limits.get("cpu"), 1.0)
        mem_b = pmem.get(name, 0.0)
        return {
            "name": name, "status": shown, "ready": ready and shown == "Running", "restarts": restarts,
            "cpu_pct": round(min(100.0, pcpu.get(name, 0.0) / cpu_limit * 100), 1) if cpu_limit else 0.0,
            "mem_pct": round(mem_b / mem_limit * 100, 1) if mem_limit else 0.0,
            "mem_mb": round(mem_b / 1024 ** 2), "limit_mb": round(mem_limit / 1024 ** 2),
            "revision": 0, "version": self._image_tag({"spec": {"containers": [container]}}), "age": 0,
        }

    # ------------------------------------------------------------------ logs / history
    async def logs(self, service: str, tail: int = 20) -> list[dict]:
        if service not in self.services:
            raise BackendError(f"unknown service {service}")
        snap = await self.snapshot()
        svc = next((s for s in snap["services"] if s["name"] == service), None)
        out: list[dict] = []
        for p in (svc["pods"] if svc else [])[:4]:
            try:
                raw = await self._k8s("GET", f"/api/v1/namespaces/{self.namespace}/pods/{p['name']}/log?tailLines={tail}")
            except BackendError:
                continue
            for line in str(raw).splitlines()[-tail:]:
                level = "ERROR" if re.search(r"\b(error|fatal|panic|exception)\b", line, re.I) else "WARN" if re.search(r"\bwarn", line, re.I) else "INFO"
                out.append({"tick": self.clock.tick, "pod": p["name"], "service": service, "level": level, "msg": line[:400]})
        return out[-tail:]

    async def _replicasets(self, deployment: str) -> tuple[dict, list[dict]]:
        dep = await self._k8s("GET", f"/apis/apps/v1/namespaces/{self.namespace}/deployments/{deployment}")
        sel = dep["spec"].get("selector", {}).get("matchLabels", {})
        query = urllib.parse.quote(",".join(f"{k}={v}" for k, v in sel.items()))
        rs = await self._k8s("GET", f"/apis/apps/v1/namespaces/{self.namespace}/replicasets?labelSelector={query}")
        mine = [r for r in rs.get("items", []) if any(o.get("name") == deployment for o in r["metadata"].get("ownerReferences", []))]
        mine.sort(key=lambda r: int(r["metadata"].get("annotations", {}).get("deployment.kubernetes.io/revision", 0)))
        return dep, mine

    async def deployments(self) -> dict[str, list[dict]]:
        out: dict[str, list[dict]] = {}
        for name in self.services:
            try:
                _, rss = await self._replicasets(name)
            except BackendError:
                continue
            out[name] = [{
                "revision": int(r["metadata"].get("annotations", {}).get("deployment.kubernetes.io/revision", 0)),
                "version": self._image_tag(r["spec"]["template"]),
                "tick": self.clock.tick,
                "note": r["metadata"].get("annotations", {}).get("kubernetes.io/change-cause") or "rollout",
            } for r in rss][-5:]
        return out

    # ------------------------------------------------------------------ actions
    def _check_ns(self, namespace: str) -> None:
        if namespace != self.namespace:
            raise BackendError(f"namespace {namespace!r} is outside this agent's scope ({self.namespace!r})")

    async def restart_pod(self, namespace: str, pod: str) -> dict:
        self._check_ns(namespace)
        await self._k8s("DELETE", f"/api/v1/namespaces/{namespace}/pods/{pod}")
        return {"ok": True, "detail": f"deleted pod {pod}; its ReplicaSet will schedule a replacement"}

    async def scale_deployment(self, namespace: str, deployment: str, replicas: int) -> dict:
        self._check_ns(namespace)
        if deployment not in self.services:
            raise BackendError(f"deployment {deployment!r} is not managed by this agent")
        await self._k8s("PATCH", f"/apis/apps/v1/namespaces/{namespace}/deployments/{deployment}/scale",
                        {"spec": {"replicas": int(replicas)}}, "application/merge-patch+json")
        return {"ok": True, "detail": f"scaled {deployment} to {replicas} replicas"}

    async def rollback_deployment(self, namespace: str, deployment: str) -> dict:
        """Equivalent of `kubectl rollout undo`: re-apply the previous ReplicaSet's pod template."""
        self._check_ns(namespace)
        if deployment not in self.services:
            raise BackendError(f"deployment {deployment!r} is not managed by this agent")
        dep, rss = await self._replicasets(deployment)
        current = int(dep["metadata"].get("annotations", {}).get("deployment.kubernetes.io/revision", 0))
        earlier = [r for r in rss if int(r["metadata"].get("annotations", {}).get("deployment.kubernetes.io/revision", 0)) < current]
        if not earlier:
            raise BackendError(f"{deployment} has no earlier revision to roll back to")
        target = earlier[-1]
        template = json.loads(json.dumps(target["spec"]["template"]))
        for k in PRUNE:
            template.get("metadata", {}).get("labels", {}).pop(k, None)
        await self._k8s("PATCH", f"/apis/apps/v1/namespaces/{namespace}/deployments/{deployment}",
                        {"spec": {"template": template}}, "application/strategic-merge-patch+json")
        return {"ok": True, "detail": f"rolled {deployment} back to {self._image_tag(target['spec']['template'])}"}
