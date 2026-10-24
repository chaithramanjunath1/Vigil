"""A tiny instrumented microservice. The same image runs all eight services.

Environment:
  SERVICE_NAME   name used in metrics and logs (gateway, cart, ...)
  DOWNSTREAMS    comma list of  name=url  this service calls on each request
  BASE_LATENCY_MS  simulated work per request (default 15)
  REQUIRED_CONFIG  if set to "strict", the process refuses to start when
                   <SERVICE_NAME>_TAX_API_URL is missing: used to simulate a bad release

Fault switches (POST, no auth: this is a demo workload, keep it cluster-internal):
  /chaos/leak    start leaking ~1 MiB per second
  /chaos/pool    pretend the DB pool is exhausted: slow, failing responses
  /chaos/reset   clear faults (a restart also clears them)

Exposes /metrics in Prometheus text format and /healthz.
"""
import json
import os
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAME = os.environ.get("SERVICE_NAME", "demo")
PORT = int(os.environ.get("PORT", "8080"))
BASE_MS = float(os.environ.get("BASE_LATENCY_MS", "15"))
DOWNSTREAMS = dict(p.split("=", 1) for p in os.environ.get("DOWNSTREAMS", "").split(",") if "=" in p)
BUCKETS = [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]

if os.environ.get("REQUIRED_CONFIG") == "strict" and not os.environ.get(f"{NAME.upper()}_TAX_API_URL"):
    print(f'{{"level":"error","msg":"panic: required environment variable {NAME.upper()}_TAX_API_URL is not set"}}', flush=True)
    print('{"level":"error","msg":"config validation failed: unknown provider \'v2\'"}', flush=True)
    sys.exit(1)

lock = threading.Lock()
requests = {}                       # status -> count
hist = [0] * (len(BUCKETS) + 1)     # cumulative-by-bucket counts
hist_sum = 0.0
hist_count = 0
leak = []
faults = {"leak": False, "pool": False}


def observe(status: int, seconds: float) -> None:
    global hist_sum, hist_count
    with lock:
        requests[str(status)] = requests.get(str(status), 0) + 1
        hist_sum += seconds
        hist_count += 1
        for i, b in enumerate(BUCKETS):
            if seconds <= b:
                hist[i] += 1
        hist[-1] += 1


def leaker() -> None:
    while True:
        time.sleep(1)
        if faults["leak"]:
            leak.append(bytearray(1024 * 1024))
            if len(leak) % 20 == 0:
                print(f'{{"level":"warn","msg":"heap {len(leak)}Mi, gc pause {20 + len(leak)}ms, cache entries growing"}}', flush=True)


def metrics_text() -> str:
    lab = f'service="{NAME}"'
    out = ["# TYPE http_requests_total counter"]
    with lock:
        for status, n in sorted(requests.items()):
            out.append(f'http_requests_total{{{lab},status="{status}"}} {n}')
        out.append("# TYPE http_request_duration_seconds histogram")
        for i, b in enumerate(BUCKETS):
            out.append(f'http_request_duration_seconds_bucket{{{lab},le="{b}"}} {hist[i]}')
        out.append(f'http_request_duration_seconds_bucket{{{lab},le="+Inf"}} {hist[-1]}')
        out.append(f"http_request_duration_seconds_sum{{{lab}}} {hist_sum:.6f}")
        out.append(f"http_request_duration_seconds_count{{{lab}}} {hist_count}")
    return "\n".join(out) + "\n"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send(self, code: int, body: str, ctype: str = "application/json") -> None:
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path.startswith("/chaos/"):
            what = self.path.rsplit("/", 1)[1]
            if what == "reset":
                faults.update(leak=False, pool=False)
                leak.clear()
            elif what in faults:
                faults[what] = True
            else:
                return self._send(404, '{"error":"unknown fault"}')
            print(json.dumps({"level": "warn", "msg": f"fault switch: {what}"}), flush=True)
            return self._send(200, json.dumps({"faults": faults}))
        self._send(404, '{"error":"not found"}')

    def do_GET(self):
        if self.path == "/metrics":
            return self._send(200, metrics_text(), "text/plain; version=0.0.4")
        if self.path == "/healthz":
            return self._send(200, '{"status":"ok"}')
        start = time.perf_counter()
        status = 200
        time.sleep(BASE_MS / 1000)
        if faults["pool"]:
            time.sleep(2.5)
            print('{"level":"warn","msg":"timeout waiting for connection from pool (size=20, in_use=20, waiting=37)"}', flush=True)
            status = 503
        else:
            for dname, url in DOWNSTREAMS.items():
                try:
                    with urllib.request.urlopen(url, timeout=3) as r:
                        if r.status >= 500:
                            status = 502
                except Exception:
                    status = 502
        observe(status, time.perf_counter() - start)
        self._send(status, json.dumps({"service": NAME, "status": status}))


if __name__ == "__main__":
    threading.Thread(target=leaker, daemon=True).start()
    print(json.dumps({"level": "info", "msg": f"{NAME} listening on :{PORT}"}), flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
