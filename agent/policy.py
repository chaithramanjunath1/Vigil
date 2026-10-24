"""Guardrails. The LLM proposes; this module decides what may actually run.

Every check is deterministic code that the model cannot talk its way past.
A decision is one of:
  allow     run it now
  approve   a human must approve first
  deny      refuse (the incident is escalated instead)
Each decision carries a list of named checks so the UI can show *why*.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Check:
    name: str
    passed: bool
    detail: str

    def as_dict(self) -> dict:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}


@dataclass
class Decision:
    verdict: str                     # allow | approve | deny
    checks: list[Check] = field(default_factory=list)
    reason: str = ""
    action: dict | None = None       # the action after policy clamping

    def as_dict(self) -> dict:
        return {"verdict": self.verdict, "reason": self.reason,
                "checks": [c.as_dict() for c in self.checks], "action": self.action}


class PolicyEngine:
    def __init__(self, spec: dict, mode: str = "auto") -> None:
        self.p = spec["policy"]
        self.namespace = spec["namespace"]
        self.service_names = {s["name"] for s in spec["services"]}
        self.mode = mode
        self.history: list[dict] = []     # executed actions: {tick, service, type}

    # --------------------------------------------------------------- bookkeeping
    def record(self, tick: int, service: str, action_type: str) -> None:
        self.history.append({"tick": tick, "service": service, "type": action_type})

    def reset(self) -> None:
        self.history = []

    def recent(self, service: str, tick: int, window: int = 90) -> list[dict]:
        return [{"service": h["service"], "type": h["type"], "ticks_ago": tick - h["tick"]}
                for h in self.history if h["service"] == service and tick - h["tick"] <= window]

    # --------------------------------------------------------------- resolution
    @staticmethod
    def owner_of(target: str, snap: dict) -> tuple[str | None, dict | None]:
        """Map a pod or deployment name to (service, pod_dict|None)."""
        for s in snap["services"]:
            if s["name"] == target:
                return s["name"], None
            for p in s["pods"]:
                if p["name"] == target:
                    return s["name"], p
        return None, None

    # --------------------------------------------------------------- evaluation
    def evaluate(self, diagnosis: dict, snap: dict, tick: int, quarantined: int = 0, human_approved: bool = False) -> Decision:
        a = dict(diagnosis["action"])
        checks: list[Check] = []
        atype = a["type"]

        def fail(name: str, detail: str, reason: str) -> Decision:
            checks.append(Check(name, False, detail))
            return Decision("deny", checks, reason, a)

        allowed = self.p["allowed_actions"]
        if atype not in allowed:
            return fail("action allowlist", f"'{atype}' is not in the allowed set {allowed}",
                        f"Refused: '{atype}' is not an action this agent is permitted to take.")
        checks.append(Check("action allowlist", True, f"{atype} is permitted"))

        if atype == "escalate":
            checks.append(Check("no cluster change", True, "escalation touches nothing in the cluster"))
            return Decision("allow", checks, "Escalating to a human.", a)

        service, pod = self.owner_of(a["target"], snap)
        if service is None:
            return fail("target exists", f"'{a['target']}' matches no pod or deployment in the cluster",
                        "Refused: the proposed target does not exist.")
        checks.append(Check("target exists", True, f"{a['target']} resolved to deployment {service}"))
        if atype == "restart_pod" and pod is None:
            return fail("target type", "restart_pod needs a pod name, got a deployment", "Refused: wrong target type.")
        if atype != "restart_pod" and pod is not None:
            return fail("target type", f"{atype} needs a deployment name, got a pod", "Refused: wrong target type.")

        if self.namespace not in self.p["allowed_namespaces"]:
            return fail("namespace scope", f"namespace {self.namespace} is outside the allowed scope", "Refused: out of scope.")
        checks.append(Check("namespace scope", True, f"limited to namespace '{self.namespace}'"))

        svc = next(s for s in snap["services"] if s["name"] == service)

        if atype == "scale_deployment":
            requested = a.get("replicas")
            if requested is None:
                return fail("replica bounds", "no replica count supplied", "Refused: scale needs a replica count.")
            lo, hi = self.p["min_replicas"], self.p["max_replicas"]
            cap = min(hi, int(svc["desired"] * self.p["max_scale_factor"]))
            clamped = max(lo, min(cap, requested))
            if clamped != requested:
                checks.append(Check("replica bounds", True,
                                    f"requested {requested}, clamped to {clamped} (max {hi}, at most {self.p['max_scale_factor']}x current {svc['desired']})"))
                a["replicas"] = clamped
            else:
                checks.append(Check("replica bounds", True, f"{requested} is within {lo} to {cap}"))
            if a["replicas"] == svc["desired"]:
                return fail("changes something", f"{service} already has {svc['desired']} replicas", "Refused: nothing to change.")

        if atype == "restart_pod" and svc["desired"] > 0:
            ready_after = svc["ready"] - (1 if pod["ready"] else 0)
            frac = ready_after / svc["desired"]
            ok = frac >= self.p["min_available_fraction"] or svc["desired"] == 1
            detail = (f"{ready_after} of {svc['desired']} replicas stay ready ({frac:.0%}); floor is {self.p['min_available_fraction']:.0%}"
                      if svc["desired"] > 1 else "single-replica service: restart cannot reduce availability further")
            if not ok:
                return fail("availability floor", detail, "Refused: restarting would take too much capacity offline.")
            checks.append(Check("availability floor", True, detail))

        if atype == "rollback_deployment":
            checks.append(Check("rollback has a target", True, f"{service} has {svc['revision']} revisions to return to"
                                if svc["revision"] > 1 else "revision history exists"))
            if svc["revision"] <= 1:
                checks[-1].passed = False
                checks[-1].detail = f"{service} has no earlier revision"
                return Decision("deny", checks, "Refused: nothing to roll back to.", a)

        recent = [h for h in self.history if h["service"] == service and tick - h["tick"] < self.p["cooldown_ticks"]]
        if recent:
            return fail("cooldown", f"{service} was already changed {tick - recent[-1]['tick']} ticks ago (cooldown {self.p['cooldown_ticks']})",
                        "Refused: too soon after the previous action on this service.")
        checks.append(Check("cooldown", True, f"no action on {service} in the last {self.p['cooldown_ticks']} ticks"))

        window = [h for h in self.history if tick - h["tick"] < self.p["window_ticks"]]
        if len(window) >= self.p["max_actions_per_window"]:
            return fail("rate limit", f"{len(window)} actions already taken in the last {self.p['window_ticks']} ticks "
                                      f"(cap {self.p['max_actions_per_window']})", "Refused: action budget used up. This looks like a flapping system.")
        checks.append(Check("rate limit", True, f"{len(window)} of {self.p['max_actions_per_window']} actions used in the window"))

        conf, floor = diagnosis["confidence"], self.p["min_confidence_auto"]
        needs_human = False
        reason = "All guardrails passed."
        if atype in self.p["approval_required"]:
            needs_human = True
            reason = f"{atype} is high impact, so a human must approve it."
            checks.append(Check("approval policy", True, f"{atype} always requires approval"))
        if conf < floor:
            needs_human = True
            reason = f"Confidence {conf:.0%} is below the {floor:.0%} needed to act alone."
            checks.append(Check("confidence floor", False, f"{conf:.0%} < {floor:.0%}, needs approval"))
        else:
            checks.append(Check("confidence floor", True, f"{conf:.0%} meets the {floor:.0%} floor"))
        if quarantined:
            needs_human = True
            reason = "Log content tried to instruct the agent, so a human must confirm."
            checks.append(Check("untrusted input", False, f"{quarantined} log line(s) tried to give the agent orders and were quarantined"))
        if human_approved:
            checks.append(Check("human approval", True, "a person approved this action; hard limits were re-checked just now"))
            return Decision("allow", checks, "Approved by a human and re-validated against the live cluster.", a)
        if self.mode == "observe":
            return Decision("approve", checks + [Check("autonomy mode", False, "observe-only: nothing runs without a human")],
                            "Observe-only mode: waiting for a human.", a)
        if self.mode == "approve":
            needs_human = True
            checks.append(Check("autonomy mode", False, "approval mode: every change needs a human"))
            reason = "Approval mode: every change needs a human."
        return Decision("approve" if needs_human else "allow", checks, reason, a)
