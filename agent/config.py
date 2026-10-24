"""Settings and the shared scenario/policy spec.

The spec lives in web/scenarios.json so the Python agent and the in-browser demo
engine are driven by exactly the same cluster topology, thresholds and policy.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC_PATH = ROOT / "web" / "scenarios.json"


def load_spec(path: str | os.PathLike | None = None) -> dict:
    return json.loads(Path(path or SPEC_PATH).read_text(encoding="utf-8"))


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


@dataclass
class Settings:
    backend: str = "simulation"          # simulation | kubernetes
    namespace: str = "shop"
    tick_seconds: float = 1.0
    speed: float = 2.0                   # simulation speed multiplier
    mode: str = "auto"                   # observe | approve | auto
    seed: int = 7

    # LLM
    llm_provider: str = "auto"           # auto | gemini | openai_compat | offline
    llm_model: str = ""
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_timeout: float = 25.0

    # Real-cluster mode
    prometheus_url: str = "http://prometheus.monitoring.svc:9090"
    poll_seconds: float = 10.0

    # Safety and hosting
    api_token: str = ""                  # if set, POST endpoints require "Authorization: Bearer <token>"
    allow_chaos: bool = True
    autopilot: bool = False              # public demo: inject a random failure whenever the cluster is calm
    cors_origins: str = "*"
    data_dir: str = "data"
    port: int = 8000

    @classmethod
    def from_env(cls) -> "Settings":
        s = cls()
        s.backend = _env("BACKEND", s.backend).lower()
        s.namespace = _env("NAMESPACE", s.namespace)
        s.tick_seconds = float(_env("TICK_SECONDS", str(s.tick_seconds)))
        s.speed = float(_env("SPEED", str(s.speed)))
        s.mode = _env("AUTONOMY_MODE", s.mode).lower()
        s.seed = int(_env("SEED", str(s.seed)))

        s.llm_provider = _env("LLM_PROVIDER", s.llm_provider).lower()
        gemini_key = _env("GEMINI_API_KEY")
        s.llm_api_key = _env("LLM_API_KEY") or gemini_key
        s.llm_base_url = _env("LLM_BASE_URL")
        s.llm_model = _env("LLM_MODEL") or _env("GEMINI_MODEL")
        s.llm_timeout = float(_env("LLM_TIMEOUT", str(s.llm_timeout)))

        s.prometheus_url = _env("PROMETHEUS_URL", s.prometheus_url)
        s.poll_seconds = float(_env("POLL_SECONDS", str(s.poll_seconds)))

        s.api_token = _env("API_TOKEN")
        s.allow_chaos = _env("ALLOW_CHAOS", "true").lower() in ("1", "true", "yes")
        s.autopilot = _env("AUTOPILOT", "false").lower() in ("1", "true", "yes")
        s.cors_origins = _env("CORS_ORIGINS", s.cors_origins)
        s.data_dir = _env("DATA_DIR", s.data_dir)
        s.port = int(_env("PORT", str(s.port)))
        return s
