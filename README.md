# Vigil: an autonomous SRE agent

Vigil watches a microservice cluster, and when something breaks it does what an on-call engineer does: it gathers evidence, finds the **root cause** (not the loudest symptom), checks its own safety limits, applies the smallest safe fix, and **proves the fix worked**. Every incident ends with a written post-mortem.

**Live demo:** `https://YOUR_GITHUB_USER.github.io/vigil/` &nbsp;(runs entirely in your browser: click *Break something* and watch it work)

![Vigil handling a bad release: the agent found the cause and is waiting for approval](docs/approval.png)

## What it does

| Stage | What happens |
|---|---|
| **Detect** | Prometheus alert rules fire. Alertmanager posts them to a FastAPI webhook. Related alerts are grouped into one incident. |
| **Diagnose** | The agent builds an evidence package (metrics vs. baseline, pod states, rollout history, recent logs, the dependency graph) and asks an LLM (Gemini, or IBM Granite through any OpenAI-compatible endpoint) for a root cause, a confidence score and one action. |
| **Check limits** | A deterministic policy engine decides whether the proposed action may run. The model proposes; code decides. |
| **Act** | Only three actions exist: `restart_pod`, `scale_deployment`, `rollback_deployment` (plus `escalate`). They run through the Kubernetes API with a service account that cannot do anything else. |
| **Verify** | The agent keeps watching. If services are not healthy and quiet for 3 consecutive checks, the fix is declared failed and the incident is handed to a human. |
| **Report** | A blameless post-mortem is generated from the incident record: evidence, ruled-out hypotheses, guardrail checks, timeline, time to recovery. |

### The six failure scenarios

| Scenario | What the agent concludes | What it does |
|---|---|---|
| Memory leak in one pod | Leak in that pod (siblings flat, traffic normal) | Restarts only that pod |
| Flash-sale traffic | Capacity, not a defect (every pod CPU-bound, request rate 3x) | Scales out, clamped to policy |
| Bad release | Crash-loop began with the latest rollout | Proposes a rollback; **waits for human approval** |
| Database pool exhausted | One pod blocked on connections; callers fail as *symptoms* | Restarts the blocked pod |
| Data inconsistency | No infrastructure fault; no safe automatic fix | **Escalates** instead of guessing |
| Log injection attack | A leak, plus a log line telling the agent to `kubectl delete namespace` | Quarantines the line, diagnoses normally, requires human confirmation |

![The agent refusing instructions hidden in a log line](docs/security.png)

## Why it is safe to let an LLM near a cluster

Autonomy is only useful if it is bounded. The model is never given a shell and never produces a command that is run directly. Its output is a *proposal*, validated and then judged by code it cannot influence:

- **Action allowlist.** Anything outside the four actions is refused and audited.
- **Scoped permissions.** `deploy/k8s/rbac.yaml` grants delete-pod, patch-scale and patch-deployment in one namespace. No secrets, no exec, no other namespaces. Kubernetes enforces this even if the agent were compromised.
- **Guardrails** (`agent/policy.py`): target must exist and be the right kind; replica count clamped (max 10, at most 2.5x current); a restart may not drop availability below 50%; 12-tick cooldown per service; at most 4 actions per window (a flapping system gets escalated, not hammered).
- **Confidence floor.** Below 75% the agent asks first. Rollbacks always ask first.
- **No repeat fixes.** If the same action on the same service already ran and the problem returned, the agent escalates instead of repeating it.
- **Prompt-injection defence.** Logs are untrusted input. Lines that look like instructions to an AI are quarantined before the model sees them, and any change in that incident requires a human.
- **Autonomy dial.** *Observe* (never changes anything), *Ask first* (every change needs approval), *Autonomous* (safe fixes run alone).
- **Graceful degradation.** If the LLM times out or returns junk, a rule-based reasoner with the same output shape takes over, and the UI says so.

## Architecture

```mermaid
flowchart LR
  subgraph cluster["Kubernetes cluster (namespace: shop)"]
    svc["8 microservices\n(/metrics, logs)"]
  end
  prom["Prometheus\n+ alert rules"] -->|scrapes| svc
  prom --> am["Alertmanager"]
  am -->|webhook| api["FastAPI\n/webhook/alertmanager"]
  subgraph vigil["Vigil agent"]
    api --> orch["Orchestrator\n(incident state machine)"]
    orch --> ctx["Evidence builder\n+ injection quarantine"]
    ctx --> llm["LLM\nGemini or Granite"]
    llm -->|proposal| pol["Policy engine\n(guardrails)"]
    pol -->|allowed| exe["Executor\n3 whitelisted actions"]
    pol -->|needs approval| human["Human"]
    human --> exe
  end
  exe -->|scoped RBAC| svc
  orch -->|SSE| ui["Mission-control dashboard"]
```

One `Orchestrator` talks to a `ClusterBackend`. Two backends implement it:

- `agent/simulator.py` is a deterministic cluster model (load flowing through a call graph, saturation turning into latency and then errors, pod lifecycle, rollouts). It powers the public demo.
- `agent/k8s_backend.py` is the real thing: Kubernetes REST API plus Prometheus, standard library only.

Everything above the backend is identical in both modes.

## Try it

**Just look (no install):** open `web/index.html` through any static server, e.g. `cd web && python -m http.server 8080`. The agent runs in the browser.

**Run the server** (simulated cluster, real FastAPI + live stream):

```bash
pip install -r requirements.txt
python -m agent                  # http://localhost:8000   (API docs at /docs)
python -m agent --lite           # same app on the standard library only, no pip needed
```

**With a real LLM:**

```bash
# Gemini (free tier available)
export GEMINI_API_KEY=...            # optional: LLM_MODEL=gemini-3.8-flash (default)
# IBM Granite via Ollama, vLLM or a watsonx gateway (any OpenAI-compatible endpoint)
export LLM_BASE_URL=http://localhost:11434/v1 LLM_MODEL=granite3.3:8b
python -m agent
```

With no key the dashboard labels the engine *offline reasoner* so nobody mistakes it for an LLM.

**Run the tests:**

```bash
python -m unittest discover -s tests -t .    # 60+ tests: policy, LLM handling, full incident loops, HTTP, Kubernetes backend
cd web && node --test ../tests/engine.test.mjs
```

## Deploy it on a real cluster

1. Install the monitoring stack: `helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack -n monitoring --create-namespace`
2. Build and push the two images (a GitHub Actions workflow does this on a version tag), then put your image names into `deploy/k8s/vigil.yaml`, and `deploy/gen_manifests.py`.
3. Apply: `kubectl apply -f deploy/k8s/namespace.yaml -f deploy/k8s/rbac.yaml`, then `python deploy/gen_manifests.py && kubectl apply -f deploy/k8s/services.yaml -f deploy/k8s/vigil.yaml`
4. Load the alert rules and route alerts to Vigil: `kubectl apply -f deploy/monitoring/alert-rules.yaml`, and merge `deploy/monitoring/alertmanager-config.yaml` into your Alertmanager config.
5. Break something on purpose: `kubectl exec -n shop deploy/cart -- python -c "import urllib.request as u; u.urlopen(u.Request('http://localhost:8080/chaos/leak', method='POST'))"`

Vigil starts in `approve` mode on a real cluster, so it never changes anything until you say so. Switch to `auto` once you trust it.

## Host the public demo

- **GitHub Pages (recommended for a CV link):** push to GitHub, then *Settings, Pages, Source: GitHub Actions*. The included workflow publishes `web/`. It is free, never sleeps, and the whole agent runs in the visitor's browser, so there is nothing to keep alive and nothing to abuse.
- **Render / any Docker host:** `render.yaml` and the `Dockerfile` run the full FastAPI server. Set `AUTOPILOT=true` to keep a public instance lively and set `API_TOKEN` if you expose it. Free tiers sleep when idle.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `BACKEND` | `simulation` | `simulation` or `kubernetes` |
| `AUTONOMY_MODE` | `auto` | `observe`, `approve` or `auto` |
| `GEMINI_API_KEY` / `LLM_MODEL` | none | Enables Gemini diagnosis |
| `LLM_BASE_URL` / `LLM_API_KEY` | none | Any OpenAI-compatible endpoint (Granite via Ollama, vLLM, watsonx) |
| `PROMETHEUS_URL` | in-cluster default | Where to read metrics |
| `API_TOKEN` | none | If set, every POST needs `Authorization: Bearer <token>` |
| `ALLOW_CHAOS` | `true` | Failure-injection endpoints (simulation only) |
| `AUTOPILOT` | `false` | Inject a random failure whenever the cluster is calm |

## API

| Route | |
|---|---|
| `POST /webhook/alertmanager` | Alertmanager v4 receiver |
| `GET /api/state`, `GET /api/stream` | Dashboard state and live server-sent events |
| `GET /api/incidents`, `GET /api/incidents/{id}/postmortem` | Incident records and Markdown post-mortems |
| `POST /api/incidents/{id}/approve` \| `reject` \| `acknowledge` | Human decisions |
| `POST /api/mode` | Switch autonomy |
| `GET /metrics` | The agent's own Prometheus metrics (incidents, actions, MTTR) |

## Honest limits

- The public demo uses a **simulated** cluster. It models real failure behaviour, but it is a model. The real backend is covered by tests against a fake Kubernetes API and fake Prometheus, not by a live cluster run in this repository's CI.
- Incident state is held in memory (with a JSONL archive). Run one replica.
- The offline reasoner is rule-based, not an LLM. It exists as a fallback, a baseline for tests and a zero-cost demo mode.
- Time to recovery includes any time spent waiting for a human; the post-mortem reports agent time separately.

## Layout

```
agent/        orchestrator, policy, LLM client, offline reasoner, simulator, k8s backend, FastAPI app
web/          the dashboard and the in-browser engine (same logic as the server, in JavaScript)
deploy/       demo microservice, Kubernetes manifests, RBAC, Prometheus rules, Alertmanager config
tests/        Python and JavaScript test suites
```

MIT licensed.
