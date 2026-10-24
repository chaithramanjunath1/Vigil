"""Blameless post-mortem, generated from the incident record (no extra LLM call)."""
from __future__ import annotations


def _list(items: list[str]) -> str:
    return "\n".join(f"- {i}" for i in items) if items else "- none recorded"


def human_wait_ticks(inc: dict) -> int:
    """Ticks between 'waiting for human approval' and the human's answer (or timeout)."""
    start = None
    for e in inc.get("timeline", []):
        if e["kind"] != "approval":
            continue
        if start is None and e["title"].startswith("Waiting"):
            start = e["tick"]
        elif start is not None:
            return e["tick"] - start
    return 0


def build_postmortem(inc: dict, seconds_per_tick: float = 1.0) -> str:
    d = inc.get("diagnosis") or {}
    act = inc.get("action") or {}
    dec = inc.get("decision") or {}
    ver = inc.get("verification") or {}

    def secs(t: int | None) -> str:
        return "n/a" if t is None else f"{t * seconds_per_tick:.0f}s"

    detected = inc["opened_tick"]
    resolved = inc.get("closed_tick")
    ttd_diag = (inc.get("diagnosed_tick") - detected) if inc.get("diagnosed_tick") is not None else None
    ttr = (resolved - detected) if resolved is not None else None

    wait = human_wait_ticks(inc)

    lines = [
        f"# {inc['id']}: {inc['title']}",
        "",
        f"**Status:** {inc['status']}  ",
        f"**Severity:** {inc['severity']}  ",
        f"**Service:** {inc.get('culprit_service') or 'unknown'}  ",
        f"**Time to diagnosis:** {secs(ttd_diag)}  ",
        f"**Time to recovery:** {secs(ttr)}  ",
        *([f"**Of which waiting for a human:** {secs(wait)} (agent working time {secs(ttr - wait)})  "] if wait and ttr is not None else []),
        f"**Diagnosed by:** {d.get('engine', 'n/a')}"
        + (" (fallback after the LLM failed)" if d.get("fallback") else "")
        + f", confidence {int(d.get('confidence', 0) * 100)}%",
        "",
        "## What happened",
        d.get("summary") or inc.get("title", ""),
        "",
        "## Root cause",
        d.get("root_cause", "Not determined."),
        "",
        "## Evidence",
        _list(d.get("evidence", [])),
        "",
        "## Reasoning",
        d.get("reasoning", "n/a"),
        "",
        "## Alternatives the agent ruled out",
        _list(d.get("alternatives", [])),
        "",
        "## Guardrail decision",
        f"**{dec.get('verdict', 'n/a')}**: {dec.get('reason', '')}",
        "",
        _list([f"{'PASS' if c['passed'] else 'FAIL'} {c['name']}: {c['detail']}" for c in dec.get("checks", [])]),
        "",
        "## Action taken",
    ]
    if act:
        lines += [f"`{act.get('command', '')}`", "", f"Result: {act.get('result', 'not executed')}"]
    else:
        lines += ["No cluster change was made."]
    if inc.get("security"):
        lines += ["", "## Security note",
                  f"{len(inc['security'])} log line(s) contained instructions aimed at the AI agent. They were quarantined before "
                  "diagnosis and were not acted on.",
                  "", *[f"- `{s['pod']}`: {s['msg'][:160]}" for s in inc["security"][:3]]]
    lines += ["", "## Verification",
              ver.get("detail", "Recovery was not verified."),
              "", "## Timeline", *[f"- t+{e['tick'] - detected}: **{e['title']}**. {e.get('detail', '')}".rstrip() for e in inc["timeline"]]]
    return "\n".join(lines) + "\n"
