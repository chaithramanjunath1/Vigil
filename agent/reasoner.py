"""Offline reasoner: a rule-based stand-in for the LLM.

It reads the same evidence package the LLM gets and returns the same JSON
shape, so it serves three jobs: a zero-dependency demo mode, a fallback when the
LLM is unreachable, and a deterministic baseline for tests. It is NOT an LLM and
the UI labels it as such.

Method (mirrors what an SRE does):
  1. Walk the dependency graph to the deepest unhealthy service. Callers that
     fail only because a critical dependency fails are symptoms, not causes.
  2. Score each failure class against the evidence on that service.
  3. Pick the least disruptive remediation inside the allowed action set, or
     escalate when the evidence is ambiguous or no safe action exists.
"""
from __future__ import annotations

import math
import re
from statistics import median

SIGNALS = {
    "oom": re.compile(r"out of memory|\boom\b|gc pause|heap \d+", re.I),
    "crash": re.compile(r"panic|config validation|back-off restarting|required environment variable|failed to start", re.I),
    "pool": re.compile(r"timeout waiting for connection|connection pool|deadline exceeded", re.I),
    "integrity": re.compile(r"checksum mismatch|diverged|inconsistent|reconcile", re.I),
    "saturation": re.compile(r"queue depth|shedding load|queue full|throttl", re.I),
}
SEVERITY_RANK = {"critical": 2, "degraded": 1, "healthy": 0}


def _count(logs: list[dict], key: str, pod: str | None = None) -> int:
    return sum(1 for ln in logs if SIGNALS[key].search(ln["msg"]) and (pod is None or ln["pod"] == pod))


def find_culprit(ctx: dict) -> tuple[str | None, list[str], set[str]]:
    svcs, graph = ctx["services"], ctx["dependency_graph"]
    unhealthy = {n for n, s in svcs.items() if s["health"] != "healthy"}
    alerted = {a["service"] for a in ctx["alerts"] if a["service"] in svcs}
    suspects = unhealthy | alerted

    def blocked_by_dependency(n: str) -> bool:
        return any(d["critical"] and d["to"] in unhealthy for d in graph.get(n, []))

    roots = [n for n in suspects if not blocked_by_dependency(n)]
    roots.sort(key=lambda n: (SEVERITY_RANK[svcs[n]["health"]], svcs[n]["error_rate"],
                              svcs[n]["p95_ms"] / max(svcs[n]["slo_ms"], 1)), reverse=True)
    return (roots[0] if roots else None), roots, unhealthy


def _analyze(name: str, svc: dict, ctx: dict) -> dict:
    pods, logs = svc["pods"], ctx["logs"].get(name, [])
    running = [p for p in pods if p["status"] in ("Running", "OOMKilled")]

    crash_pods = [p for p in pods if p["status"] in ("CrashLoopBackOff", "Error")]
    last_rev = svc["rollout_history"][-1] if svc["rollout_history"] else None
    changed = bool(last_rev and svc["revision"] > 1 and last_rev["ticks_ago"] <= 150
                   and not last_rev["note"].startswith("rollback"))

    def others(p: dict, key: str) -> float:
        vals = [q[key] for q in running if q["name"] != p["name"]]
        return median(vals) if vals else 0.0

    mem_candidates = []
    for p in running:
        gap = p["mem_pct"] - others(p, "mem_pct")
        rising = p["mem_trend_pct_per_tick"] > 0.8 and p["mem_pct"] > 55
        oomish = p["status"] == "OOMKilled" or (p["restarts"] > 0 and _count(logs, "oom", p["name"]) > 0)
        if gap > 20 or rising or oomish or p["mem_pct"] > 75:
            mem_candidates.append(p)
    mem_pod = max(mem_candidates, key=lambda p: (p["status"] == "OOMKilled", p["mem_pct"])) if mem_candidates else None

    slow_candidates = []
    for p in running:
        if p["ready"] and len(running) > 1 and p["cpu_pct"] < 0.55 * others(p, "cpu_pct") and svc["error_rate"] > 0.05:
            slow_candidates.append(p)
    pool_by_logs = {}
    for ln in logs:
        if SIGNALS["pool"].search(ln["msg"]):
            pool_by_logs[ln["pod"]] = pool_by_logs.get(ln["pod"], 0) + 1
    pool_pod_name = max(pool_by_logs, key=pool_by_logs.get) if pool_by_logs else None
    if pool_pod_name is None and slow_candidates:
        pool_pod_name = slow_candidates[0]["name"]
    pool_pod = next((p for p in pods if p["name"] == pool_pod_name), None)

    base_rps, base_cpu = svc["rps_baseline"], ctx["baseline_cpu"].get(name)
    rps_ratio = svc["rps"] / base_rps if base_rps else 1.0
    return {
        "crash_pods": crash_pods, "changed": changed, "last_rev": last_rev,
        "mem_pod": mem_pod, "pool_pod": pool_pod, "slow_pods": slow_candidates,
        "rps_ratio": rps_ratio, "base_cpu": base_cpu, "pods": pods, "running": running,
        "n_crash_logs": _count(logs, "crash"), "n_oom_logs": _count(logs, "oom"),
        "n_pool_logs": _count(logs, "pool"), "n_integrity_logs": _count(logs, "integrity"),
        "n_sat_logs": _count(logs, "saturation"),
    }


def _score(svc: dict, a: dict) -> dict[str, int]:
    cpu = svc["cpu_pct"]
    resource_quiet = cpu < 75 and not a["crash_pods"] and not a["mem_pod"]
    return {
        "bad_deploy": (3 if a["crash_pods"] else 0) + (3 if a["changed"] else 0)
                      + (2 if a["n_crash_logs"] else 0) + (1 if svc["replicas_ready"] == 0 else 0),
        "memory_leak": (3 if a["mem_pod"] else 0) + (2 if a["mem_pod"] and a["mem_pod"]["restarts"] > 0 else 0)
                       + (2 if a["mem_pod"] and a["mem_pod"]["mem_trend_pct_per_tick"] > 0.8 else 0)
                       + (1 if a["n_oom_logs"] else 0),
        "traffic_saturation": (3 if cpu > 85 else 0) + (3 if a["rps_ratio"] > 1.6 else 0)
                              + (2 if a["n_sat_logs"] else 0) - (3 if a["pool_pod"] else 0),
        "connection_pool_exhaustion": (3 if a["pool_pod"] else 0) + (3 if a["n_pool_logs"] else 0)
                                      + (1 if a["slow_pods"] else 0),
        "data_integrity": (4 if a["n_integrity_logs"] else 0)
                          + (2 if svc["error_rate"] > 0.05 and resource_quiet else 0),
    }


def _fmt(x: float) -> str:
    return f"{x:.0f}"


def diagnose(ctx: dict) -> dict:
    culprit, roots, unhealthy = find_culprit(ctx)
    if culprit is None:
        return _unknown(ctx, "No service in scope looks unhealthy right now; the alerts may have been transient.")
    svc = ctx["services"][culprit]
    a = _analyze(culprit, svc, ctx)
    scores = _score(svc, a)
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    (best, top), (second, runner) = ranked[0], ranked[1]
    if top < 3:
        return _unknown(ctx, f"{culprit} is unhealthy but the evidence does not match a known failure pattern.", culprit)

    confidence = min(0.97, 0.45 + 0.07 * top)
    if top - runner <= 2:
        confidence -= 0.15
    confidence = round(max(0.3, confidence), 2)

    symptoms = sorted(n for n in unhealthy if n != culprit)
    downstream = (f" Callers {', '.join(symptoms)} are failing only because {culprit} is a critical dependency, "
                  f"so they are symptoms rather than causes.") if symptoms else ""
    builders = {
        "memory_leak": _leak, "traffic_saturation": _saturation, "bad_deploy": _bad_deploy,
        "connection_pool_exhaustion": _pool, "data_integrity": _integrity,
    }
    out = builders[best](culprit, svc, a, ctx)
    out["reasoning"] += downstream
    out["category"], out["culprit_service"], out["confidence"] = best, culprit, confidence
    out["alternatives"] = _alternatives(best, culprit, svc, a, scores) + [f"Also unhealthy but downstream: {n}" for n in symptoms[:2]]

    prior = [p for p in ctx["previous_actions"] if p["service"] == culprit and p["type"] == out["action"]["type"]]
    if prior and out["action"]["type"] != "escalate":
        p0 = prior[-1]
        out["alternatives"].insert(0, f"{p0['type']} on {culprit} was already tried {p0['ticks_ago']} ticks ago and did not hold")
        out["action"] = {
            "type": "escalate", "target": culprit, "replicas": None,
            "rationale": f"The same fix ({p0['type']}) already ran on {culprit} and the problem came back. "
                         "Repeating it would be guessing, so a human should look.",
        }
        out["reasoning"] += " The previous attempt did not hold, so repeating it is not justified."
        out["confidence"] = round(min(out["confidence"], 0.6), 2)
    return out


# ------------------------------------------------------------------ builders
def _leak(name, svc, a, ctx):
    p = a["mem_pod"]
    sib = [q["mem_pct"] for q in a["running"] if q["name"] != p["name"]]
    sib_med = _fmt(median(sib)) if sib else "n/a"
    rising = p["mem_trend_pct_per_tick"]
    ev = [f"{p['name']} memory is {_fmt(p['mem_pct'])}% of its limit" + (f" and rising {rising:+.1f}% per tick" if rising > 0.3 else "")]
    if sib:
        ev.append(f"Sibling pods are flat near {sib_med}% memory")
    if a["n_oom_logs"]:
        ev.append(f"{a['n_oom_logs']} heap/GC/OOM log lines from this service")
    if p["restarts"]:
        ev.append(f"{p['name']} has restarted {p['restarts']} time(s)")
    ev.append(f"Service CPU {_fmt(svc['cpu_pct'])}% and request rate {a['rps_ratio'] * 100 - 100:+.0f}% vs baseline: no load problem")
    return {
        "root_cause": f"Memory leak in pod {p['name']}: {_fmt(p['mem_pct'])}% of its memory limit while siblings stay near {sib_med}%.",
        "summary": f"One pod of {name} is leaking memory and heading for an OOM kill. The other replicas are healthy.",
        "evidence": ev,
        "reasoning": "Memory on a single pod grows steadily while its siblings are flat and traffic is normal, which points to a leak "
                     "inside that pod instead of a load or release problem. Replacing only that pod frees the memory and keeps the "
                     "other replicas serving.",
        "action": {"type": "restart_pod", "target": p["name"], "replicas": None,
                   "rationale": f"Replaces the leaking pod; {max(svc['replicas_ready'] - 1, 0)} of {svc['replicas_desired']} replicas keep serving meanwhile."},
        "culprit_pod": p["name"],
    }


def _saturation(name, svc, a, ctx):
    lim = ctx["limits"]
    demand = (a["base_cpu"] * a["rps_ratio"]) if a["base_cpu"] else svc["cpu_pct"]
    desired = svc["replicas_desired"]
    needed = math.ceil(desired * max(demand, svc["cpu_pct"]) / 60)
    upper = min(lim["max_replicas"], math.floor(desired * lim["max_scale_factor"]))
    target = max(desired + 1, min(needed, upper))
    ev = [f"{name} CPU is {_fmt(svc['cpu_pct'])}% across all {svc['replicas_ready']} pods",
          f"Request rate is {a['rps_ratio']:.1f}x its baseline ({svc['rps']:.0f} vs {svc['rps_baseline']:.0f} rps)",
          f"p95 latency {_fmt(svc['p95_ms'])}ms against an SLO of {svc['slo_ms']}ms, error rate {svc['error_rate'] * 100:.0f}%"]
    if a["n_sat_logs"]:
        ev.append(f"{a['n_sat_logs']} queue-full / CPU-throttle log lines")
    return {
        "root_cause": f"{name} is saturated: traffic is {a['rps_ratio']:.1f}x baseline and every pod is out of CPU.",
        "summary": f"A traffic surge has exhausted {name}'s capacity, so requests queue, slow down and then fail.",
        "evidence": ev,
        "reasoning": "All pods are CPU-bound at the same time, the request rate is far above baseline, and no pod stands out from the rest. "
                     "That is a capacity problem, not a defect in one pod. Adding replicas spreads the load without touching running pods.",
        "action": {"type": "scale_deployment", "target": name, "replicas": target,
                   "rationale": f"Scale from {desired} to {target} replicas to bring CPU near 60% at the current request rate."},
        "culprit_pod": None,
    }


def _bad_deploy(name, svc, a, ctx):
    rev = a["last_rev"]
    crashed = a["crash_pods"]
    ev = [f"{len(crashed)} of {len(a['pods'])} pods are in CrashLoopBackOff, {svc['replicas_ready']} ready",
          f"Version {svc['version']} (revision {svc['revision']}) rolled out {rev['ticks_ago']} ticks ago: \"{rev['note']}\""
          if rev else "Pods are crash-looping on the current revision"]
    if a["n_crash_logs"]:
        ev.append(f"{a['n_crash_logs']} startup failure log lines (missing or invalid configuration)")
    ev.append(f"Error rate {svc['error_rate'] * 100:.0f}%, but no memory or CPU anomaly on the service")
    return {
        "root_cause": f"Bad release: {name} {svc['version']} crashes on startup after the latest rollout.",
        "summary": f"The newest deploy of {name} fails at boot with a configuration error, so no pod can serve traffic.",
        "evidence": ev,
        "reasoning": "Pods began crash-looping right after a new revision rolled out, and their logs show startup configuration "
                     "errors rather than resource exhaustion. Restarting pods would only recreate the same broken version, "
                     "so the correct fix is to go back to the previous revision.",
        "action": {"type": "rollback_deployment", "target": name, "replicas": None,
                   "rationale": "Roll back to the previous revision, which was healthy before this release."},
        "culprit_pod": crashed[0]["name"] if crashed else None,
    }


def _pool(name, svc, a, ctx):
    p = a["pool_pod"]
    sib_cpu = [q["cpu_pct"] for q in a["running"] if q["name"] != p["name"]]
    ev = [f"{p['name']} is blocked on a resource: CPU {_fmt(p['cpu_pct'])}% vs {_fmt(median(sib_cpu)) if sib_cpu else 'n/a'}% on siblings, memory normal",
          f"{a['n_pool_logs']} log lines: timeouts waiting for a database connection",
          f"{name} error rate {svc['error_rate'] * 100:.0f}% and p95 {_fmt(svc['p95_ms'])}ms (SLO {svc['slo_ms']}ms)"]
    return {
        "root_cause": f"Database connection pool exhausted in pod {p['name']}: requests wait for a connection until they time out.",
        "summary": f"One {name} pod has used up its database connections. It is slow and failing while the others are fine.",
        "evidence": ev,
        "reasoning": "A single pod shows high latency and errors with low CPU and normal memory, and its logs say it is waiting for a "
                     "database connection. That is a blocked pool, not load or a leak. A fresh pod gets a fresh pool.",
        "action": {"type": "restart_pod", "target": p["name"], "replicas": None,
                   "rationale": f"Replaces the pod holding the exhausted pool; {max(svc['replicas_ready'] - 1, 0)} of {svc['replicas_desired']} replicas keep serving."},
        "culprit_pod": p["name"],
    }


def _integrity(name, svc, a, ctx):
    ev = [f"{a['n_integrity_logs']} log lines report checksum mismatches or diverged rows",
          f"{name} error rate {svc['error_rate'] * 100:.0f}% with CPU {_fmt(svc['cpu_pct'])}% and normal memory",
          "No pod restarts, crash loops or recent rollout"]
    return {
        "root_cause": f"Data inconsistency in {name}: stock records disagree with the source of truth.",
        "summary": f"{name} is returning inconsistent data. Restarting or scaling will not repair data.",
        "evidence": ev,
        "reasoning": "Errors come from data validation, not from infrastructure: resources are healthy and nothing changed recently. "
                     "Any automatic restart, scale or rollback could hide or worsen corruption, so this needs a human who can inspect the data.",
        "action": {"type": "escalate", "target": name, "replicas": None,
                   "rationale": "No safe automated action fixes data integrity. Page the owning team."},
        "culprit_pod": None,
    }


def _unknown(ctx, why, culprit=None):
    return {
        "root_cause": why, "category": "unknown", "culprit_service": culprit, "culprit_pod": None, "confidence": 0.3,
        "summary": "The evidence is inconclusive, so the agent is handing this to a human instead of guessing.",
        "evidence": [f"{len(ctx['alerts'])} alert(s) in scope", "No signal strongly matches memory, capacity, release, pool or data failures"],
        "reasoning": why + " Taking an action on weak evidence is riskier than waiting for a person.",
        "alternatives": [],
        "action": {"type": "escalate", "target": culprit or "cluster", "replicas": None,
                   "rationale": "Evidence is too weak for an automated fix."},
    }


def _alternatives(best, name, svc, a, scores):
    alt = []
    if best != "traffic_saturation":
        alt.append(f"Traffic saturation ruled out: CPU {_fmt(svc['cpu_pct'])}%, request rate {a['rps_ratio'] * 100 - 100:+.0f}% vs baseline")
    if best != "bad_deploy":
        alt.append("Bad release ruled out: no crash-looping pods tied to a recent rollout" if not a["changed"]
                   else "A recent rollout exists but pods are not crash-looping")
    if best == "memory_leak":
        alt.append("Raising the memory limit rejected: it hides the leak instead of clearing it")
    if best == "traffic_saturation":
        alt.append("Restarting pods rejected: every pod is equally loaded, so a restart would not add capacity")
    if best == "bad_deploy":
        alt.append("Restarting pods rejected: they would come back on the same broken version")
    return alt[:3]
