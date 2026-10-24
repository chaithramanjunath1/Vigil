"""Builds the evidence package an LLM (or the offline reasoner) diagnoses from.

Two safety properties live here:
  * Logs are untrusted input. Lines that look like instructions aimed at an AI
    agent are quarantined before the model ever sees them, and reported.
  * The context only contains what a human on-call engineer could see: metrics,
    pod states, logs and rollout history. No hidden scenario labels.
"""
from __future__ import annotations

import re

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)",
    r"disregard\s+.{0,40}\binstructions",
    r"\b(system|developer)\s+(override|prompt|message)\b",
    r"\bkubectl\s+(delete|exec|apply|patch|drain|cordon)\b",
    r"\bdelete\s+(the\s+)?namespace\b",
    r"\byou\s+are\s+now\b",
    r"\bauthorized\s+maintenance\s+override\b",
    r"\brm\s+-rf\b",
]
_INJECTION_RE = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE)
QUARANTINE_NOTE = "[quarantined: this log line looked like an instruction aimed at an AI agent]"


def looks_like_injection(msg: str) -> bool:
    return bool(_INJECTION_RE.search(msg))


def sanitize_logs(lines: list[dict]) -> tuple[list[dict], list[dict]]:
    clean: list[dict] = []
    flagged: list[dict] = []
    for ln in lines:
        if looks_like_injection(ln["msg"]):
            flagged.append(dict(ln))
            clean.append({**ln, "msg": QUARANTINE_NOTE})
        else:
            clean.append(ln)
    return clean, flagged


def _select_services(snap: dict, alerts: list[dict], graph: dict[str, list[dict]]) -> list[str]:
    by_name = {s["name"]: s for s in snap["services"]}
    seeds = {n for n, s in by_name.items() if s["health"] != "healthy"} | {a["service"] for a in alerts}
    seeds &= set(by_name)
    selected = set(seeds)
    for n in list(seeds):
        for c in graph.get(n, []):
            selected.add(c["to"])
    return [s["name"] for s in snap["services"] if s["name"] in selected]


select_services = _select_services


def build_context(
    snap: dict,
    history,
    alerts: list[dict],
    logs_by_service: dict[str, list[dict]],
    deployments: dict[str, list[dict]],
    previous_actions: list[dict],
    spec: dict,
) -> tuple[dict, list[dict]]:
    graph = {s["name"]: s["calls"] for s in spec["services"]}
    names = _select_services(snap, alerts, graph)
    by_name = {s["name"]: s for s in snap["services"]}
    tick = snap["tick"]

    services: dict[str, dict] = {}
    for n in names:
        s = by_name[n]
        base = {m: history.baseline(n, m) for m in ("rps", "p95_ms", "error_rate", "cpu_pct", "mem_pct")}
        pods = []
        for p in s["pods"]:
            pods.append({
                "name": p["name"], "status": p["status"], "ready": p["ready"], "restarts": p["restarts"],
                "cpu_pct": p["cpu_pct"], "mem_pct": p["mem_pct"],
                "mem_trend_pct_per_tick": history.pod_trend(p["name"], "mem_pct"),
                "version": p["version"], "age_ticks": p["age"],
            })
        revs = deployments.get(n, [])
        services[n] = {
            "health": s["health"], "replicas_desired": s["desired"], "replicas_ready": s["ready"],
            "rps": s["rps"], "rps_baseline": round(base["rps"], 1) if base["rps"] else None,
            "p95_ms": s["p95_ms"], "p95_baseline_ms": round(base["p95_ms"], 1) if base["p95_ms"] else None,
            "slo_ms": s["slo_ms"], "error_rate": s["error_rate"],
            "cpu_pct": s["cpu_pct"], "mem_pct": s["mem_pct"],
            "version": s["version"], "revision": s["revision"],
            "rollout_history": [
                {"revision": r["revision"], "version": r["version"], "ticks_ago": tick - r["tick"], "note": r["note"]}
                for r in revs[-3:]
            ],
            "pods": pods,
        }

    quarantined: list[dict] = []
    logs: dict[str, list[dict]] = {}
    for n in names:
        raw = logs_by_service.get(n, [])
        important = [ln for ln in raw if ln["level"] != "INFO"]
        routine = [ln for ln in raw if ln["level"] == "INFO"][-3:]
        merged = sorted(important[-10:] + routine, key=lambda ln: ln["tick"])[-12:]
        # injection lines are INFO-level in the sim, so scan the whole tail too
        merged_ids = {id(x) for x in merged}
        merged += [ln for ln in raw[-30:] if looks_like_injection(ln["msg"]) and id(ln) not in merged_ids][-2:]
        merged.sort(key=lambda ln: ln["tick"])
        clean, flagged = sanitize_logs(merged)
        quarantined += flagged
        logs[n] = [{"ticks_ago": tick - ln["tick"], "pod": ln["pod"], "level": ln["level"], "msg": ln["msg"]} for ln in clean]

    pol = spec["policy"]
    ctx = {
        "namespace": spec["namespace"],
        "alerts": [{"alertname": a["name"], "service": a["service"], "pod": a.get("pod"),
                    "severity": a["severity"], "summary": a["summary"]} for a in alerts],
        "dependency_graph": {n: [{"to": c["to"], "critical": c["critical"]} for c in graph.get(n, [])] for n in names},
        "services": services,
        "baseline_cpu": {n: (round(history.baseline(n, "cpu_pct"), 1) if history.baseline(n, "cpu_pct") else None) for n in names},
        "logs": logs,
        "previous_actions": previous_actions,
        "untrusted_log_lines_quarantined": len(quarantined),
        "limits": {
            "allowed_actions": pol["allowed_actions"], "min_replicas": pol["min_replicas"],
            "max_replicas": pol["max_replicas"], "max_scale_factor": pol["max_scale_factor"],
        },
    }
    return ctx, quarantined
