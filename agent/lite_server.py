"""Zero-dependency HTTP server (asyncio streams).

Runs the same API as the FastAPI app: `python -m agent --lite`. Useful when you
cannot install packages, and it is what the test-suite uses to exercise real
HTTP + server-sent events end to end.
"""
from __future__ import annotations

import asyncio
import mimetypes
from pathlib import Path

from .api_core import Api, ApiError
from .config import ROOT, Settings
from .factory import autopilot, build_orchestrator

WEB = ROOT / "web"
REASONS = {200: "OK", 204: "No Content", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
           405: "Method Not Allowed", 409: "Conflict", 413: "Payload Too Large", 429: "Too Many Requests",
           500: "Internal Server Error", 503: "Service Unavailable"}
MAX_HEADER = 16_384


class LiteServer:
    def __init__(self, settings: Settings, web_dir: Path = WEB) -> None:
        self.settings = settings
        self.web = web_dir.resolve()
        self.orch = build_orchestrator(settings)
        self.api = Api(self.orch, settings)
        self._server: asyncio.AbstractServer | None = None
        self._bg: list[asyncio.Task] = []

    # ------------------------------------------------------------------ lifecycle
    async def start(self, host: str = "0.0.0.0", port: int | None = None) -> int:
        await self.orch.start()
        if self.settings.autopilot and hasattr(self.orch.backend, "inject"):
            self._bg.append(asyncio.create_task(autopilot(self.orch)))
        self._server = await asyncio.start_server(self._client, host, self.settings.port if port is None else port)
        return self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        for t in self._bg:
            t.cancel()
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        await self.orch.stop()

    # ------------------------------------------------------------------ http
    def _head(self, status: int, ctype: str, length: int | None, extra: dict | None = None) -> bytes:
        h = [f"HTTP/1.1 {status} {REASONS.get(status, 'OK')}", f"Content-Type: {ctype}",
             f"Access-Control-Allow-Origin: {self.settings.cors_origins}",
             "Access-Control-Allow-Headers: authorization, content-type", "Access-Control-Allow-Methods: GET, POST, OPTIONS",
             "X-Content-Type-Options: nosniff", "Connection: close"]
        if length is not None:
            h.append(f"Content-Length: {length}")
        for k, v in (extra or {}).items():
            h.append(f"{k}: {v}")
        return ("\r\n".join(h) + "\r\n\r\n").encode()

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
            if len(raw) > MAX_HEADER:
                return
            lines = raw.decode("latin-1").split("\r\n")
            method, target, _ = lines[0].split(" ", 2)
            headers = {}
            for ln in lines[1:]:
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            body = b""
            n = int(headers.get("content-length", 0) or 0)
            if n > 1_000_000:
                writer.write(self._head(413, "application/json", 2) + b"{}")
            else:
                if n:
                    body = await asyncio.wait_for(reader.readexactly(n), timeout=10)
                await self._dispatch(method.upper(), target, headers, body, writer)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, asyncio.LimitOverrunError, ConnectionError, ValueError):
            pass
        finally:
            try:
                await writer.drain()
            except ConnectionError:
                pass
            writer.close()

    async def _dispatch(self, method, target, headers, body, writer) -> None:
        path = target.split("?", 1)[0]
        if method == "GET" and path == "/api/stream":
            await self._sse(writer)
            return
        if path.startswith(("/api/", "/webhook/")) or path in ("/healthz", "/metrics"):
            status, ctype, payload = await self.api.handle(method, target, body, headers)
            writer.write(self._head(status, ctype, len(payload)) + (payload if method != "HEAD" else b""))
            return
        if method not in ("GET", "HEAD"):
            writer.write(self._head(405, "text/plain", 0))
            return
        self._static(path, writer)

    async def _sse(self, writer) -> None:
        try:
            gen = self.api.stream()
            first = await gen.__anext__()
        except ApiError as e:
            msg = e.message.encode()
            writer.write(self._head(e.status, "text/plain", len(msg)) + msg)
            return
        writer.write(self._head(200, "text/event-stream", None, {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}))
        try:
            writer.write(first.encode())
            await writer.drain()
            async for chunk in gen:
                writer.write(chunk.encode())
                await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            await gen.aclose()

    def _static(self, path: str, writer) -> None:
        rel = path.lstrip("/") or "index.html"
        target = (self.web / rel).resolve()
        if self.web not in target.parents and target != self.web:  # blocks ../ traversal
            writer.write(self._head(403, "text/plain", 0))
            return
        if target.is_dir():
            target = target / "index.html"
        if not target.is_file():
            msg = b"not found"
            writer.write(self._head(404, "text/plain", len(msg)) + msg)
            return
        data = target.read_bytes()
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
            ctype += "; charset=utf-8"
        writer.write(self._head(200, ctype, len(data), {"Cache-Control": "no-cache"}) + data)


async def serve(settings: Settings) -> None:
    srv = LiteServer(settings)
    port = await srv.start()
    print(f"Vigil ({srv.orch.backend.name}, engine: {srv.orch.diagnoser.label}) listening on http://localhost:{port}")
    try:
        await asyncio.Event().wait()
    finally:
        await srv.stop()
