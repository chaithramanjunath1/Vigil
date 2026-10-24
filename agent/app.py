"""FastAPI application: `uvicorn agent.app:app`.

Route logic lives in api_core.Api (shared with the stdlib server). This module
only adapts it to FastAPI: typed request bodies for the OpenAPI docs at /docs,
an SSE stream, CORS, and the static dashboard.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .api_core import Api, ApiError
from .config import ROOT, Settings
from .factory import autopilot, build_orchestrator

settings = Settings.from_env()
orch = build_orchestrator(settings)
api = Api(orch, settings)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await orch.start()
    bg = []
    if settings.autopilot and hasattr(orch.backend, "inject"):
        bg.append(asyncio.create_task(autopilot(orch)))
    yield
    for t in bg:
        t.cancel()
    await orch.stop()


app = FastAPI(
    title="Vigil: autonomous SRE agent",
    description="Receives alerts, diagnoses root cause with an LLM, and fixes the cluster inside strict guardrails.",
    version="1.0.0",
    lifespan=lifespan,
)
origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins or ["*"], allow_methods=["GET", "POST"], allow_headers=["*"])


# ---------------------------------------------------------------- helpers
async def _call(request: Request, method: str, path: str, body: bytes | None = None) -> Response:
    query = request.url.query
    target = path + (f"?{query}" if query else "")
    status, ctype, payload = await api.handle(method, target, body if body is not None else await request.body(), dict(request.headers))
    return Response(content=payload, status_code=status, media_type=ctype)


class ChaosBody(BaseModel):
    scenario: str = Field(..., examples=["memory_leak"])
    target: str | None = Field(None, examples=["cart"])


class HealBody(BaseModel):
    service: str


class ModeBody(BaseModel):
    mode: str = Field(..., examples=["auto"], description="observe | approve | auto")


class SpeedBody(BaseModel):
    speed: float = Field(..., ge=0.25, le=20)


class PauseBody(BaseModel):
    paused: bool


class DecisionBody(BaseModel):
    by: str = "operator"
    note: str = ""


# ---------------------------------------------------------------- read
@app.get("/healthz", tags=["ops"])
async def healthz(request: Request):
    return await _call(request, "GET", "/healthz")


@app.get("/metrics", tags=["ops"], description="Agent self-metrics in Prometheus text format")
async def metrics(request: Request):
    return await _call(request, "GET", "/metrics")


@app.get("/api/state", tags=["dashboard"])
async def state(request: Request):
    return await _call(request, "GET", "/api/state")


@app.get("/api/config", tags=["dashboard"])
async def config(request: Request):
    return await _call(request, "GET", "/api/config")


@app.get("/api/incidents", tags=["incidents"])
async def incidents(request: Request):
    return await _call(request, "GET", "/api/incidents")


@app.get("/api/incidents/{iid}", tags=["incidents"])
async def incident(iid: str, request: Request):
    return await _call(request, "GET", f"/api/incidents/{iid}")


@app.get("/api/incidents/{iid}/postmortem", tags=["incidents"])
async def postmortem(iid: str, request: Request):
    return await _call(request, "GET", f"/api/incidents/{iid}/postmortem")


@app.get("/api/logs/{service}", tags=["dashboard"])
async def logs(service: str, request: Request):
    return await _call(request, "GET", f"/api/logs/{service}")


@app.get("/api/stream", tags=["dashboard"], description="Server-sent events: full state, then ticks and incident updates")
async def stream():
    gen = api.stream()
    try:
        first = await gen.__anext__()
    except ApiError as e:
        return JSONResponse({"error": e.message}, status_code=e.status)

    async def body():
        try:
            yield first
            async for chunk in gen:
                yield chunk
        finally:
            await gen.aclose()

    return StreamingResponse(body(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------- write
@app.post("/webhook/alertmanager", tags=["alerts"], description="Alertmanager webhook receiver (v4 payload)")
async def alertmanager(request: Request):
    return await _call(request, "POST", "/webhook/alertmanager")


@app.post("/api/incidents/{iid}/approve", tags=["incidents"])
async def approve(iid: str, request: Request, body: DecisionBody | None = None):
    return await _call(request, "POST", f"/api/incidents/{iid}/approve")


@app.post("/api/incidents/{iid}/reject", tags=["incidents"])
async def reject(iid: str, request: Request, body: DecisionBody | None = None):
    return await _call(request, "POST", f"/api/incidents/{iid}/reject")


@app.post("/api/incidents/{iid}/acknowledge", tags=["incidents"])
async def acknowledge(iid: str, request: Request):
    return await _call(request, "POST", f"/api/incidents/{iid}/acknowledge")


@app.post("/api/mode", tags=["controls"])
async def mode(body: ModeBody, request: Request):
    return await _call(request, "POST", "/api/mode")


@app.post("/api/speed", tags=["controls"])
async def speed(body: SpeedBody, request: Request):
    return await _call(request, "POST", "/api/speed")


@app.post("/api/pause", tags=["controls"])
async def pause(body: PauseBody, request: Request):
    return await _call(request, "POST", "/api/pause")


@app.post("/api/chaos", tags=["simulation"], description="Inject a failure into the simulated cluster")
async def chaos(body: ChaosBody, request: Request):
    return await _call(request, "POST", "/api/chaos")


@app.post("/api/chaos/heal", tags=["simulation"], description="Stand-in for a human fixing the root cause")
async def heal(body: HealBody, request: Request):
    return await _call(request, "POST", "/api/chaos/heal")


@app.post("/api/reset", tags=["simulation"])
async def reset(request: Request):
    return await _call(request, "POST", "/api/reset")


# ---------------------------------------------------------------- dashboard (must be last)
app.mount("/", StaticFiles(directory=str(ROOT / "web"), html=True), name="web")
