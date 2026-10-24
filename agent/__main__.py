"""`python -m agent` starts the server.

    python -m agent            FastAPI + uvicorn if installed, else the stdlib server
    python -m agent --lite     force the zero-dependency server
"""
from __future__ import annotations

import argparse
import asyncio

from .config import Settings


def main() -> None:
    ap = argparse.ArgumentParser(prog="agent", description="Vigil autonomous SRE agent")
    ap.add_argument("--lite", action="store_true", help="use the dependency-free stdlib server")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=None)
    args = ap.parse_args()
    settings = Settings.from_env()
    if args.port:
        settings.port = args.port

    if not args.lite:
        try:
            import uvicorn  # noqa: F401
            import fastapi  # noqa: F401
        except ImportError:
            print("fastapi/uvicorn not installed, falling back to the stdlib server (pip install -r requirements.txt for FastAPI)")
            args.lite = True
    if args.lite:
        from .lite_server import serve
        asyncio.run(serve(settings))
        return
    import os

    import uvicorn
    os.environ["PORT"] = str(settings.port)
    uvicorn.run("agent.app:app", host=args.host, port=settings.port, log_level="info")


if __name__ == "__main__":
    main()
