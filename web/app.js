// Vigil dashboard. Talks to the Vigil server when one is reachable, otherwise runs the same agent in the browser.
// Every string that reaches the page goes through textContent (never innerHTML): workload logs are untrusted.

import { Engine } from "./engine.js";

const REPO_URL = ""; // set to your GitHub repo URL to show a "View source" link
const params = new URLSearchParams(location.search);
const API = (params.get("api") || "").replace(/\/$/, "");

// ------------------------------------------------------------------ dom helpers
const NS = "http://www.w3.org/2000/svg";
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  add(el, kids);
  return el;
}
function s(tag, attrs, ...kids) {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v != null && v !== false) el.setAttribute(k, v);
  add(el, kids);
  return el;
}
function add(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k == null || k === false) continue;
    el.append(k.nodeType ? k : document.createTextNode(String(k)));
  }
}
const $ = (id) => document.getElementById(id);
const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); return el; };

const ICONS = {
  check: "M5 12.5l4.5 4.5L19 7", x: "M6 6l12 12M18 6L6 18",
  alert: "M12 3L2.5 20h19L12 3zM12 10v4.5M12 17.2v.3",
  leak: "M12 3s6 6.5 6 11a6 6 0 0 1-12 0c0-4.5 6-11 6-11z",
  surge: "M3 17l5-6 4 4 8-9M15 6h5v5",
  release: "M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3zM4 7.5l8 4.5 8-4.5M12 12v9",
  pool: "M9 3v5M15 3v5M6 8h12v3a6 6 0 0 1-12 0V8zM12 17v4",
  data: "M5 9h14M5 15h14M16 5L8 19",
  shield: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3zM12 8v5M12 16v.5",
  dot: "M12 12m-2.5 0a2.5 2.5 0 1 0 5 0a2.5 2.5 0 1 0 -5 0",
};
const SCN_ICON = { memory_leak: "leak", traffic_spike: "surge", bad_deploy: "release", pool_exhaustion: "pool", data_drift: "data", poisoned_logs: "shield" };
const SCN_TAG = {
  memory_leak: "Restarts only the leaking pod", traffic_spike: "Scales the service out", bad_deploy: "Rolls back once you approve",
  pool_exhaustion: "Restarts the blocked pod", data_drift: "Hands off to a human", poisoned_logs: "Ignores the attack, then asks you first",
};
function icon(name, cls) {
  return s("svg", { viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": "2.2", "stroke-linecap": "round", "stroke-linejoin": "round", class: cls, "aria-hidden": "true" }, s("path", { d: ICONS[name] }));
}

const f1 = (v) => (Math.round(v * 10) / 10).toString();
const ms = (v) => `${Math.round(v)} ms`;
const pct = (v) => `${(v * 100).toFixed(v < 0.1 ? 1 : 0)}%`;

// ------------------------------------------------------------------ state
const S = {
  spec: null, config: { mode: "auto", seconds_per_tick: 1, backend: "simulation", engine: "", engine_is_llm: false, policy: {} },
  snap: { tick: 0, services: [], edges: [] }, alerts: [], hist: {}, incidents: new Map(), archive: [], scenarios: [],
  selected: null, pinned: false, openSvc: null, mode: "live", engine: null, demoDone: false, connected: false,
};
const spt = () => S.config.seconds_per_tick || 1;
const secs = (t) => `${Math.round(t * spt())} s`;
const svcByName = (n) => S.snap.services.find((x) => x.name === n);

// ------------------------------------------------------------------ transport
async function send(method, path, body) {
  if (S.mode === "local") {
    const r = await S.engine.request(method, path, body || {});
    return r;
  }
  try {
    const res = await fetch(API + path, { method, headers: { "Content-Type": "application/json" }, body: method === "POST" ? JSON.stringify(body || {}) : undefined });
    const ct = res.headers.get("content-type") || "";
    return ct.includes("json") ? { status: res.status, data: await res.json() } : { status: res.status, text: await res.text() };
  } catch (e) { return { status: 0, data: { error: "Cannot reach the server" } }; }
}
async function act(path, body, okMsg) {
  const r = await send("POST", path, body);
  if (r.status >= 400 || r.status === 0) toast(r.data?.error || "That did not work", "bad");
  else if (okMsg) toast(okMsg, "ok");
  return r;
}

async function connect() {
  S.spec = await (await fetch("scenarios.json", { cache: "no-store" })).json();
  let initial = null;
  if (params.get("mode") !== "local") {
    try { const r = await fetch(API + "/api/state", { cache: "no-store" }); if (r.ok && (r.headers.get("content-type") || "").includes("json")) initial = await r.json(); } catch { /* fall through to browser mode */ }
  }
  if (initial) {
    S.mode = "live"; onEvent({ type: "state", data: initial }); openStream();
  } else {
    S.mode = "local";
    S.engine = new Engine(S.spec, { speed: 2, autopilot: false });
    for (let i = 0; i < 24; i++) S.engine.tick(); // pre-roll so the first paint is a healthy, warmed-up cluster
    S.engine.on(onEvent);
    onEvent({ type: "state", data: S.engine.state() });
    S.engine.start();
    $("auto").hidden = false;
  }
}
let es = null, retry = 1000;
function openStream() {
  es = new EventSource(API + "/api/stream");
  for (const t of ["state", "tick", "incident", "alert_resolved", "config", "reset", "chaos", "action", "error"]) {
    es.addEventListener(t, (e) => { try { onEvent({ type: t, data: JSON.parse(e.data) }); } catch { /* ignore a malformed frame */ } });
  }
  es.onopen = () => { S.connected = true; retry = 1000; setWatch(); };
  es.onerror = () => { S.connected = false; setWatch(); es.close(); setTimeout(openStream, retry); retry = Math.min(retry * 2, 10000); };
}

// ------------------------------------------------------------------ events
function onEvent({ type, data }) {
  switch (type) {
    case "state": {
      S.config = data.config; S.snap = data.snapshot; S.alerts = data.alerts; S.scenarios = data.scenarios; S.archive = data.archive || [];
      S.hist = {};
      const hs = data.history?.services || {};
      for (const [n, m] of Object.entries(hs)) S.hist[n] = Object.fromEntries(Object.entries(m).map(([k, v]) => [k, [...v]]));
      S.incidents = new Map(data.incidents.map((i) => [i.id, i]));
      if (!S.selected || !S.incidents.has(S.selected)) { S.selected = newestId(); S.pinned = false; }
      buildTopology(); buildBoard(); renderAll(); break;
    }
    case "tick": {
      S.snap = { ...S.snap, tick: data.tick, services: data.services }; S.alerts = data.alerts;
      for (const sv of data.services) {
        const hh = (S.hist[sv.name] ||= { rps: [], p95_ms: [], error_rate: [], cpu_pct: [], mem_pct: [] });
        for (const k of Object.keys(hh)) { hh[k].push(sv[k]); if (hh[k].length > 120) hh[k].shift(); }
      }
      updateTopology(); updateBoard(); updateVitals(); updateLive(); maybeDemo(); break;
    }
    case "incident": {
      const isNew = !S.incidents.has(data.id);
      S.incidents.set(data.id, data);
      if (isNew && !S.pinned) S.selected = data.id;
      if (!S.selected) S.selected = data.id;
      renderCase(); renderLedger(); updateTopology(); updateVitals();
      if (isNew) toast(`${data.id} opened: ${data.title}`, "bad");
      if (data.status === "resolved" && data.verification?.ok) toast(`${data.id} resolved in ${secs(data.closed_tick - data.opened_tick)}`, "ok");
      break;
    }
    case "config": S.config = data; renderBar(); break;
    case "reset": S.incidents.clear(); S.selected = null; S.pinned = false; S.demoDone = true; renderAll(); break;
    case "chaos": if (data.scenario) toast(`${data.auto ? "Autopilot injected" : "Injected"}: ${data.title} on ${data.target}`); else if (data.healed) toast(`Simulated a human fix on ${data.healed}`, "ok"); break;
    case "action": pulse(data.service); break;
    case "error": toast(data.message, "bad"); break;
  }
}
const newestId = () => [...S.incidents.values()].sort((a, b) => b.opened_tick - a.opened_tick)[0]?.id || null;

function maybeDemo() {
  if (S.mode !== "local" || S.demoDone || params.get("autoplay") === "0") return;
  if (S.snap.tick >= 30 && S.incidents.size === 0) {
    S.demoDone = true;
    send("POST", "/api/chaos", { scenario: "memory_leak", target: "cart" });
    toast("Demo: a pod in cart just started leaking memory. Watch the agent find it.");
  }
}

// ------------------------------------------------------------------ top bar + vitals
function renderAll() { renderBar(); updateVitals(); renderCase(); renderLedger(); renderMenu(); updateTopology(); updateBoard(); renderFoot(); }
function setWatch() {
  const pods = S.snap.services.reduce((n, x) => n + x.pods.length, 0);
  let t = S.mode === "live" && !S.connected && es ? "Reconnecting" : `Watching ${S.config.namespace}: ${S.snap.services.length} services, ${pods} pods`;
  $("watch").textContent = t;
}
function renderBar() {
  setWatch();
  document.querySelectorAll("#dial button").forEach((b) => b.setAttribute("aria-checked", String(b.dataset.mode === S.config.mode)));
  document.querySelectorAll("#speed button").forEach((b) => b.classList.toggle("on", +b.dataset.speed === S.config.speed));
  const p = $("pause"); p.setAttribute("aria-pressed", String(!!S.config.paused)); p.textContent = S.config.paused ? "Resume" : "Pause";
  const e = $("engine"); e.textContent = S.config.engine || "Offline reasoner"; e.classList.toggle("llm", !!S.config.engine_is_llm);
  const hasChaos = S.config.chaos_enabled !== false; $("breakBtn").hidden = !hasChaos;
  $("auto").setAttribute("aria-pressed", String(!!S.engine?.autopilot));
}
function updateVitals() {
  const sv = S.snap.services; if (!sv.length) return;
  const gw = sv.find((x) => x.name === "gateway") || sv[0];
  const ready = sv.reduce((n, x) => n + x.ready, 0), want = sv.reduce((n, x) => n + x.desired, 0);
  const done = [...S.incidents.values(), ...S.archive.filter((a) => !S.incidents.has(a.id))].filter((i) => i.status === "resolved" && i.closed_tick != null);
  const mttr = done.length ? done.reduce((n, i) => n + (i.closed_tick - i.opened_tick) * (i.seconds_per_tick || 1), 0) / done.length : null;
  const vit = (label, val, cls) => h("div", { class: "vital" }, h("b", { class: cls }, val), h("span", null, label));
  const box = clear($("vitals"));
  box.append(
    vit("Pods ready", `${ready} of ${want}`, ready < want ? "warn" : ""),
    vit("Gateway p95", ms(gw.p95_ms), gw.p95_ms > gw.slo_ms ? "bad" : ""),
    vit("Gateway errors", pct(gw.error_rate), gw.error_rate > 0.05 ? "bad" : ""),
    vit("Mean time to recover", mttr == null ? "none yet" : `${Math.round(mttr)} s`, ""),
  );
  setWatch();
}
function renderFoot() {
  const f = clear($("foot"));
  const txt = S.mode === "local"
    ? "This page runs entirely in your browser: the cluster is simulated and the diagnosis comes from a rule-based reasoner. Connect the Vigil server to use Gemini or IBM Granite on a live or real Kubernetes cluster."
    : `Connected to the Vigil server (${S.config.backend} backend). Diagnosis engine: ${S.config.engine}.`;
  f.append(txt, REPO_URL ? [" ", h("a", { href: REPO_URL, target: "_blank", rel: "noopener" }, "View the source")] : null);
}

// ------------------------------------------------------------------ topology
const W = 1000, HGT = 700, R = 38;
const px = (p) => 96 + p[0] * 9.1, py = (p) => 70 + p[1] * 6.2;
const N = {}; let edgesEls = [];
function buildTopology() {
  const svg = clear($("topo")); svg.setAttribute("viewBox", `0 0 ${W} ${HGT}`);
  for (const k of Object.keys(N)) delete N[k];
  edgesEls = [];
  const pos = Object.fromEntries(S.spec.services.map((x) => [x.name, [px(x.pos), py(x.pos)]]));
  const gE = s("g"), gN = s("g"); svg.append(gE, gN);
  for (const svc of S.spec.services) {
    for (const c of svc.calls) {
      const [x1, y1] = pos[svc.name], [x2, y2] = pos[c.to], sx = x1 + R + 6, ex = x2 - R - 6, cx = (sx + ex) / 2, id = `e-${svc.name}-${c.to}`;
      const path = s("path", { id, d: `M${sx} ${y1} C${cx} ${y1} ${cx} ${y2} ${ex} ${y2}`, class: `edge${c.critical ? "" : " opt"}` });
      const dots = [0, 1].map((i) => s("circle", { r: 2.6, class: "flow" }, s("animateMotion", { dur: "3.4s", begin: `${-i * 1.7}s`, repeatCount: "indefinite" }, s("mpath", { href: `#${id}` }))));
      gE.append(path, ...dots); edgesEls.push({ from: svc.name, to: c.to, path, dots });
    }
  }
  for (const svc of S.spec.services) {
    const [x, y] = pos[svc.name];
    const reticle = s("g", { class: "reticle-g", opacity: 0 }, ...[[-1, -1], [1, -1], [-1, 1], [1, 1]].map(([a, b]) =>
      s("path", { class: "reticle", d: `M${x + a * 56} ${y + b * 40} v${b * 16} h${a * -16}`.replace(/v(-?\d+)/, (m, v) => `v${-b * 0 + b * 16 * 1}`) })));
    const big = s("text", { x, y: y + 3, class: "big" }, "0"), unit = s("text", { x, y: y + 16, class: "unit" }, "ms");
    const disc = s("circle", { cx: x, cy: y, r: 29, class: "disc healthy" });
    const podsG = s("g");
    const name = s("text", { x, y: y + 60, class: "name" }, svc.name), meta = s("text", { x, y: y + 76, class: "meta" }, ""), state = s("text", { x, y: y + 92, class: "state" }, "");
    const g = s("g", { class: "node", tabindex: 0, role: "button", "aria-label": svc.name, transform: "" }, reticle, disc, podsG, big, unit, name, meta, state);
    g.addEventListener("click", () => toggleService(svc.name)); g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggleService(svc.name); } });
    gN.append(g); N[svc.name] = { g, x, y, disc, big, meta, state, podsG, reticle, key: "", names: new Set() };
  }
}
function arc(cx, cy, r, a0, a1) {
  const pt = (a) => [cx + r * Math.cos((a * Math.PI) / 180), cy + r * Math.sin((a * Math.PI) / 180)];
  const [x0, y0] = pt(a0), [x1, y1] = pt(a1);
  return `M${x0.toFixed(1)} ${y0.toFixed(1)} A${r} ${r} 0 ${a1 - a0 > 180 ? 1 : 0} 1 ${x1.toFixed(1)} ${y1.toFixed(1)}`;
}
const podClass = (p) => {
  if (["CrashLoopBackOff", "OOMKilled", "Error"].includes(p.status)) return "bad";
  if (p.status === "Pending") return "wait";
  if (!p.ready || p.mem_pct > 75) return "warn";
  return "ok";
};
function culpritOpen() {
  const inc = S.incidents.get(S.selected);
  return inc && inc.status !== "resolved" && inc.culprit_service ? inc.culprit_service : null;
}
function updateTopology() {
  if (!S.spec || !Object.keys(N).length) return;
  const culprit = culpritOpen();
  for (const sv of S.snap.services) {
    const n = N[sv.name]; if (!n) continue;
    n.disc.setAttribute("class", `disc ${sv.health}`);
    n.big.textContent = String(Math.round(sv.p95_ms));
    n.meta.textContent = `${sv.ready}/${sv.desired} ready`;
    const isT = culprit === sv.name;
    n.state.textContent = isT ? "Agent target" : sv.health === "healthy" ? "" : sv.health === "degraded" ? "Degraded" : "Critical";
    n.state.setAttribute("class", `state ${isT ? "" : sv.health}`); n.state.style.fill = isT ? "var(--agent)" : "";
    n.reticle.setAttribute("opacity", isT ? 1 : 0);
    n.g.setAttribute("aria-label", `${sv.name}, ${sv.health}, ${sv.ready} of ${sv.desired} pods ready, p95 ${Math.round(sv.p95_ms)} milliseconds`);
    const key = sv.pods.map((p) => p.name).join("|");
    if (key !== n.key) {
      clear(n.podsG); const count = sv.pods.length, step = 360 / count, gap = count > 1 ? Math.min(10, step * 0.28) : 0;
      n.podEls = sv.pods.map((p, i) => {
        const el = s("path", { class: `pod ${podClass(p)}${n.key && !n.names.has(p.name) ? " fresh" : ""}`, d: arc(n.x, n.y, 35, -90 + i * step + gap / 2, -90 + (i + 1) * step - gap / 2 - (count === 1 ? 0.01 : 0)) });
        n.podsG.append(el); return el;
      });
      n.key = key; n.names = new Set(sv.pods.map((p) => p.name));
    } else sv.pods.forEach((p, i) => n.podEls[i].setAttribute("class", `pod ${podClass(p)}`));
  }
  const by = Object.fromEntries(S.snap.services.map((x) => [x.name, x]));
  for (const e of edgesEls) {
    const callee = by[e.to]; if (!callee) continue;
    const cls = callee.error_rate > 0.05 ? "bad" : callee.p95_ms > callee.slo_ms ? "warn" : "";
    e.path.setAttribute("class", `edge${S.spec.services.find((x) => x.name === e.from).calls.find((c) => c.to === e.to).critical ? "" : " opt"} ${cls}`);
    e.dots.forEach((d) => d.setAttribute("class", `flow ${cls}`));
  }
}
function pulse(service) {
  const n = N[service]; if (!n) return;
  const r = s("circle", { cx: n.x, cy: n.y, r: 30, class: "ripple" }); r.addEventListener("animationend", () => r.remove());
  $("topo").append(r);
}

// ------------------------------------------------------------------ service board
const B = {};
function sparkPath(vals, max, w = 100, hgt = 26) {
  if (!vals.length) return "";
  const step = vals.length > 1 ? w / (vals.length - 1) : 0;
  return vals.map((v, i) => `${i ? "L" : "M"}${(i * step).toFixed(1)} ${(hgt - Math.min(1, v / max) * (hgt - 2) - 1).toFixed(1)}`).join(" ");
}
function buildBoard() {
  const box = clear($("board")); for (const k of Object.keys(B)) delete B[k];
  box.append(h("div", { class: "row head", role: "row" }, h("span", null, "Service"), h("span", null, "Pods"), h("span", null, "p95 latency"), h("span", null, "Error rate"), h("span", null, "CPU and memory")));
  for (const svc of S.spec.services) {
    const dot = h("i", { class: "dot healthy" }), pips = h("div", { class: "pips" });
    const p95v = h("span", { class: "val" }, "0 ms"), errv = h("span", { class: "val" }, "0%");
    const p95svg = s("svg", { class: "spark", viewBox: "0 0 100 26", preserveAspectRatio: "none" }, s("path", { class: "slo" }), s("path", { class: "line" }));
    const errsvg = s("svg", { class: "spark err", viewBox: "0 0 100 26", preserveAspectRatio: "none" }, s("path", { class: "line" }));
    const cpuI = h("i"), memI = h("i");
    const row = h("div", { class: "row", role: "row", tabindex: 0, "aria-expanded": "false", "aria-label": `${svc.name}, show pods and logs` },
      h("span", { class: "svc" }, dot, svc.name), pips,
      h("div", { class: "metric" }, p95svg, p95v), h("div", { class: "metric" }, errsvg, errv),
      h("div", { class: "bars" }, h("div", { class: "bar-row" }, "cpu", h("div", { class: "meter" }, cpuI)), h("div", { class: "bar-row" }, "mem", h("div", { class: "meter" }, memI))));
    row.addEventListener("click", () => toggleService(svc.name)); row.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggleService(svc.name); } });
    const wrap = h("div", { class: "grp" }, row); box.append(wrap);
    B[svc.name] = { wrap, row, dot, pips, p95v, errv, p95svg, errsvg, cpuI, memI, detail: null };
  }
}
function toggleService(name) {
  S.openSvc = S.openSvc === name ? null : name;
  for (const [n, b] of Object.entries(B)) {
    const open = n === S.openSvc; b.row.setAttribute("aria-expanded", String(open));
    if (!open && b.detail) { b.detail.remove(); b.detail = null; }
    if (open && !b.detail) { b.detail = h("div", { class: "detail" }); b.wrap.append(b.detail); b.logTick = -99; }
  }
  if (S.openSvc) { B[name].wrap.scrollIntoView({ block: "nearest", behavior: "smooth" }); updateBoard(); }
}
const stCls = (p) => ({ bad: ["CrashLoopBackOff", "OOMKilled", "Error"].includes(p.status), wait: p.status === "Pending", warn: p.status === "Running" && !p.ready })[1] ;
function statusClass(p) { const c = podClass(p); return c; }
function updateBoard() {
  for (const sv of S.snap.services) {
    const b = B[sv.name]; if (!b) continue;
    b.dot.setAttribute("class", `dot ${sv.health}`);
    const key = sv.pods.map((p) => p.name).join("|") + sv.pods.map((p) => podClass(p)).join("");
    if (b.pipKey !== key) { clear(b.pips); sv.pods.forEach((p) => b.pips.append(h("i", { class: `pip ${podClass(p) === "ok" ? "" : podClass(p)}`, title: `${p.name}: ${p.status}` }))); b.pipKey = key; }
    const hh = S.hist[sv.name] || { p95_ms: [], error_rate: [] };
    const p95 = hh.p95_ms.slice(-60), err = hh.error_rate.slice(-60), pmax = Math.max(sv.slo_ms * 1.6, ...p95);
    b.p95svg.children[1].setAttribute("d", sparkPath(p95, pmax)); const sy = 26 - Math.min(1, sv.slo_ms / pmax) * 24 - 1;
    b.p95svg.children[0].setAttribute("d", `M0 ${sy.toFixed(1)} L100 ${sy.toFixed(1)}`);
    b.errsvg.children[0].setAttribute("d", sparkPath(err, Math.max(0.3, ...err)));
    b.p95v.textContent = ms(sv.p95_ms); b.p95v.className = `val ${sv.p95_ms > sv.slo_ms * 3 ? "bad" : sv.p95_ms > sv.slo_ms ? "warn" : ""}`;
    b.errv.textContent = pct(sv.error_rate); b.errv.className = `val ${sv.error_rate > 0.25 ? "bad" : sv.error_rate > 0.05 ? "warn" : ""}`;
    const maxMem = Math.max(0, ...sv.pods.map((p) => p.mem_pct));
    b.cpuI.style.width = `${Math.min(100, sv.cpu_pct)}%`; b.cpuI.className = sv.cpu_pct > 90 ? "bad" : sv.cpu_pct > 75 ? "warn" : "";
    b.memI.style.width = `${Math.min(100, maxMem)}%`; b.memI.className = maxMem > 85 ? "bad" : maxMem > 70 ? "warn" : "";
    if (S.openSvc === sv.name && b.detail) renderDetail(sv, b);
  }
}
async function renderDetail(sv, b) {
  const rows = sv.pods.map((p) => h("tr", null, h("td", { title: p.name }, p.name), h("td", null, h("span", { class: `st ${podClass(p)}` }, p.status)), h("td", null, `${Math.round(p.mem_pct)}%`), h("td", null, `${Math.round(p.cpu_pct)}%`), h("td", null, String(p.restarts)), h("td", null, p.version)));
  const tbl = h("table", { class: "pods" }, h("thead", null, h("tr", null, ...["Pod", "State", "Mem", "CPU", "Restarts", "Version"].map((x) => h("th", null, x)))), h("tbody", null, rows));
  let logs = b.logsEl;
  if (!logs) { logs = b.logsEl = h("div", { class: "logs", role: "log", "aria-label": `${sv.name} recent logs`, tabindex: 0 }); }
  clear(b.detail).append(h("div", null, tbl), h("div", null, h("div", { class: "logs-title" }, "Recent logs"), logs));
  if (S.snap.tick - b.logTick >= 2) {
    b.logTick = S.snap.tick; const r = await send("GET", `/api/logs/${sv.name}?tail=40`);
    const lines = r.data || []; if (!Array.isArray(lines)) return;
    const stick = logs.scrollTop + logs.clientHeight >= logs.scrollHeight - 8;
    clear(logs).append(...lines.slice(-40).map((l) => h("div", { class: l.level }, h("span", { class: "p" }, `t${l.tick} ${l.pod.split("-").slice(-1)[0]} `), `${l.level} ${l.msg}`)));
    if (stick) logs.scrollTop = logs.scrollHeight;
  }
}

// ------------------------------------------------------------------ case file
let L = {}; // live refs updated every tick
const sevClass = (inc) => (inc.severity === "critical" ? "bad" : "warn");
function statusChip(inc) {
  const m = { detecting: ["Detecting", "warn"], diagnosing: ["Diagnosing", "agent"], awaiting_approval: ["Needs your approval", "warn"], executing: ["Acting", "agent"], verifying: ["Verifying", "agent"], escalated: ["Handed to a human", "bad"], resolved: ["Resolved", "ok"] }[inc.status] || [inc.status, "dim"];
  return h("span", { class: `chip ${m[1]}` }, m[0]);
}
function stepStates(inc) {
  const st = inc.status, dx = !!inc.diagnosis, dec = inc.decision, acted = inc.action;
  const o = { detect: "done", diagnose: dx ? "done" : "active", guard: dec ? "done" : dx ? "active" : "todo", act: "todo", verify: "todo" };
  if (st === "awaiting_approval") o.guard = "wait";
  if (dec?.verdict === "deny") { o.guard = "bad"; o.act = "skip"; o.verify = "skip"; }
  else if (acted) o.act = acted.ok ? "done" : "bad";
  else if (st === "executing") o.act = "active";
  else if (st === "escalated" && dec) { o.act = "skip"; o.verify = "skip"; }
  if (st === "verifying") o.verify = "active";
  if (inc.verification) o.verify = inc.verification.ok ? "done" : "bad";
  return o;
}
function renderCase() {
  const root = clear($("case")); L = {};
  const incs = [...S.incidents.values()].sort((a, b) => a.opened_tick - b.opened_tick);
  if (!incs.length) { root.append(idleView()); return; }
  if (incs.length > 1) {
    root.append(h("div", { class: "tabs", role: "tablist", "aria-label": "Incidents" }, incs.map((i) => h("button", { class: "tab", role: "tab", "aria-selected": String(i.id === S.selected), onclick: () => { S.selected = i.id; S.pinned = true; renderCase(); updateTopology(); } },
      h("i", { class: i.status === "resolved" ? "ok" : i.status === "escalated" ? "bad" : i.status === "awaiting_approval" ? "warn" : "agent" }), i.id))));
  }
  const inc = S.incidents.get(S.selected) || incs.at(-1);
  root.append(caseView(inc));
}
function idleView() {
  return h("div", { class: "idle" },
    h("h2", null, "All quiet."),
    h("p", null, `Vigil is watching ${S.snap.services.length || 8} services. Break one and watch it find the cause, check its own limits, fix the problem, and prove the fix worked.`),
    scenarioList(false));
}
function scenarioList(compact) {
  return h("div", { class: "scn" }, S.scenarios.map((sc) =>
    h("button", { type: "button", onclick: () => { closeMenu(); inject(sc.id); } },
      h("span", { class: "ic" }, icon(SCN_ICON[sc.id] || "alert")),
      h("span", null, h("b", null, sc.title), h("span", { class: "bl" }, sc.blurb), h("span", { class: "tag" }, SCN_TAG[sc.id] || "")))));
}
async function inject(id) { S.demoDone = true; await act("/api/chaos", { scenario: id }); } // a visitor acting cancels the scripted demo

function caseView(inc) {
  const d = inc.diagnosis, open = inc.status !== "resolved", frag = document.createDocumentFragment();
  L.elapsed = h("span");
  frag.append(h("div", { class: "case-top" }, h("span", null, h("b", null, inc.id), "  ", statusChip(inc)), L.elapsed));
  frag.append(h("h2", { class: "case-title" }, inc.title));
  frag.append(stepper(inc));

  if (inc.security?.length) {
    frag.append(h("div", { class: "threat", role: "note" }, h("b", null, "The agent refused instructions found in a log"),
      h("p", null, `${inc.security.length} log line(s) tried to give the agent orders. They were removed before diagnosis, and any change now needs a human.`),
      h("code", null, inc.security[0].msg)));
  }
  if (!d) {
    frag.append(h("div", { class: "block" }, h("h3", null, "Gathering evidence"), h("p", { class: "prose" }, inc.status === "detecting"
      ? "An alert fired. Vigil waits a few seconds so related alerts group into one incident, then collects metrics, pod states, logs and rollout history."
      : "Evidence collected. The engine is reasoning about the root cause.")));
    frag.append(timeline(inc)); return frag;
  }
  if (d.fallback) frag.append(h("div", { class: "warnbox" }, "The language model did not answer in time, so the built-in rule-based reasoner took over. ", d.degraded_reason || ""));
  frag.append(h("div", { class: "block" }, h("h3", null, "Diagnosis"), h("p", { class: "prose" }, d.summary), h("p", { class: "cause" }, d.root_cause), confidence(d, inc)));
  if (d.evidence?.length) frag.append(h("div", { class: "block" }, h("h3", null, "Evidence"), h("ul", { class: "list reveal" }, d.evidence.map((e, i) => h("li", { style: `--i:${i}` }, icon("dot"), e)))));
  if (d.alternatives?.length) frag.append(h("div", { class: "block" }, h("h3", null, "Ruled out"), h("ul", { class: "list ruled" }, d.alternatives.map((e) => h("li", null, icon("x"), e)))));
  if (d.reasoning) frag.append(h("div", { class: "block" }, h("h3", null, "Reasoning"), h("p", { class: "prose", style: "font-size:16px" }, d.reasoning)));
  if (inc.decision) frag.append(guardrails(inc));
  frag.append(actionBlock(inc));
  if (inc.status === "resolved") frag.append(resultBlock(inc));
  frag.append(timeline(inc));
  if (inc.status === "awaiting_approval") frag.append(gateBar(inc));
  return frag;
}
// Pinned to the bottom of the case file so the one thing a human must do is always in reach.
function gateBar(inc) {
  L.countdown = h("span", { class: "countdown" });
  return h("div", { class: "gate", role: "group", "aria-label": "Decision needed" },
    h("div", { class: "gate-q" }, h("b", null, "Run this fix?"), h("code", null, inc.proposed?.command || "")),
    h("div", { class: "actions" },
      h("button", { class: "btn go", onclick: () => act(`/api/incidents/${inc.id}/approve`, { by: "you" }) }, "Approve and run"),
      h("button", { class: "btn", onclick: () => act(`/api/incidents/${inc.id}/reject`, { by: "you" }) }, "Reject"), L.countdown));
}
function stepper(inc) {
  const st = stepStates(inc), names = [["detect", "Detect"], ["diagnose", "Diagnose"], ["guard", "Check limits"], ["act", "Act"], ["verify", "Verify"]];
  return h("ol", { class: "steps", "aria-label": "Incident progress" }, names.map(([k, label]) =>
    h("li", { class: `step ${st[k]}`, "aria-current": st[k] === "active" ? "step" : null }, h("span", { class: "n" }, st[k] === "done" ? icon("check") : st[k] === "bad" ? icon("x") : null), label)));
}
function confidence(d, inc) {
  const floor = S.config.policy?.min_confidence_auto ?? 0.75, c = d.confidence;
  return h("div", { class: "conf" }, `${d.engine}${d.fallback ? " (fallback)" : ""} is ${Math.round(c * 100)}% sure`,
    h("div", { class: "conf-bar", role: "img", "aria-label": `Confidence ${Math.round(c * 100)} percent, the agent acts alone above ${Math.round(floor * 100)} percent` }, h("i", { style: `width:${c * 100}%` }), h("u", { style: `left:${floor * 100}%` })),
    h("div", { class: "conf-note" }, h("span", null, "0%"), h("span", null, `acts alone above ${Math.round(floor * 100)}%`), h("span", null, "100%")));
}
function guardrails(inc) {
  const dec = inc.decision, v = { allow: ["Allowed to run", "allow"], approve: ["Needs a human", "approve"], deny: ["Refused", "deny"] }[dec.verdict];
  return h("div", { class: "block" }, h("h3", null, "Guardrails"),
    h("div", { class: `verdict ${v[1]}` }, icon(dec.verdict === "allow" ? "check" : dec.verdict === "deny" ? "x" : "alert", ""), h("span", null, `${v[0]}. ${dec.reason}`)),
    h("ul", { class: "checks" }, dec.checks.map((c) => h("li", null, c.passed ? icon("check", "ok-i") : icon(dec.verdict === "deny" ? "x" : "alert", dec.verdict === "deny" ? "no-i" : "soft-i"), h("span", null, h("span", { class: "nm" }, c.name), h("span", { class: "dt" }, c.detail))))));
}
function actionBlock(inc) {
  const p = inc.proposed; if (!p) return document.createDocumentFragment();
  const box = h("div", { class: "block" }, h("h3", null, inc.action ? "Action taken" : p.type === "escalate" ? "Recommended next step" : "Proposed action"));
  box.append(h("div", { class: "cmd", tabindex: 0, "aria-label": "Command" }, inc.action?.command || p.command), p.rationale ? h("p", { class: "why" }, p.rationale) : null);
  if (inc.action) box.append(h("p", { class: "why" }, `Result: ${inc.action.result}`));
  if (inc.status === "awaiting_approval") box.append(h("p", { class: "why" }, "Nothing has run. The agent is waiting for your decision."));
  if (inc.status === "escalated") {
    box.append(h("div", { class: "handoff" }, h("b", null, "A human needs to take it from here"), h("p", null, inc.escalation?.reason || "")));
    const a = [h("button", { class: "btn sm", onclick: () => act(`/api/incidents/${inc.id}/acknowledge`, {}) }, "Close incident")];
    if (S.config.chaos_enabled !== false && inc.culprit_service) a.unshift(h("button", { class: "btn sm solid", onclick: () => act("/api/chaos/heal", { service: inc.culprit_service }) }, `Simulate a human fixing ${inc.culprit_service}`));
    box.append(h("div", { class: "actions" }, a));
  }
  return box;
}
function resultBlock(inc) {
  const t = secs(inc.closed_tick - inc.opened_tick);
  return h("div", { class: "block" }, h("h3", null, "Result"), h("div", { class: "result" }, h("b", null, t), h("span", null, inc.verification?.detail || "Recovered.")),
    h("div", { class: "actions", style: "margin-top:14px" }, h("button", { class: "btn sm", onclick: () => showPostmortem(inc.id) }, "Read the post-mortem")));
}
function timeline(inc) {
  return h("div", { class: "block" }, h("h3", null, "Timeline"), h("ul", { class: "timeline" }, inc.timeline.map((e) =>
    h("li", { class: `k-${e.kind}` }, h("span", { class: "t" }, `+${Math.max(0, e.tick - inc.opened_tick)}`), h("span", null, h("span", { class: "ttl" }, e.title), e.detail ? h("span", { class: "dtl" }, e.detail) : null)))));
}
function updateLive() {
  const inc = S.incidents.get(S.selected);
  if (L.elapsed && inc && inc.status !== "resolved") L.elapsed.textContent = `${secs(S.snap.tick - inc.opened_tick)} since detection`;
  else if (L.elapsed && inc) L.elapsed.textContent = `Recovered in ${secs(inc.closed_tick - inc.opened_tick)}`;
  if (L.countdown && inc?.pending_approval) L.countdown.textContent = `Expires in ${secs(Math.max(0, inc.pending_approval.deadline_tick - S.snap.tick))}`;
}

// ------------------------------------------------------------------ ledger
function renderLedger() {
  const box = clear($("ledger"));
  const rows = new Map(S.archive.map((a) => [a.id, a]));
  for (const i of S.incidents.values()) rows.set(i.id, i);
  const list = [...rows.values()].sort((a, b) => b.opened_tick - a.opened_tick);
  if (!list.length) { box.append(h("p", { class: "empty-note" }, "No incidents yet. Use Break something to create one.")); return; }
  box.append(h("div", { class: "led head" }, h("span", null, "Incident"), h("span", null, "What went wrong"), h("span", { class: "cmdh" }, "What the agent did"), h("span", { class: "engh" }, "Recovery"), h("span", null, "Outcome")));
  for (const i of list) {
    const cmd = i.action?.command || (typeof i.action === "string" ? i.action : null);
    const dur = i.closed_tick != null ? secs(i.closed_tick - i.opened_tick) : "open";
    const outcome = i.status === "resolved" ? (i.resolved_by === "agent" ? ["Fixed by agent", "ok"] : i.resolved_by === "human" ? ["Closed by human", "dim"] : ["Recovered", "ok"]) : i.status === "escalated" ? ["With a human", "bad"] : i.status === "awaiting_approval" ? ["Needs approval", "warn"] : ["In progress", "agent"];
    box.append(h("button", { class: "led", type: "button", onclick: () => { if (S.incidents.has(i.id)) { S.selected = i.id; S.pinned = true; renderCase(); updateTopology(); document.getElementById("casefile").scrollIntoView({ behavior: "smooth", block: "start" }); } else showPostmortem(i.id); } },
      h("span", { class: "id" }, i.id), h("span", { class: "ttl" }, i.title), h("span", { class: "cmd eng" }, cmd || "No cluster change"), h("span", { class: "eng" }, dur), h("span", null, h("span", { class: `chip ${outcome[1]}` }, outcome[0]))));
  }
}

// ------------------------------------------------------------------ menus, dialogs, toasts
function renderMenu() { const m = clear($("breakMenu")); m.append(scenarioList(true)); }
function closeMenu() { $("breakMenu").hidden = true; $("breakBtn").setAttribute("aria-expanded", "false"); }
function toast(msg, kind = "") {
  const t = h("div", { class: `toast ${kind}`, role: "status" }, msg); $("toasts").append(t);
  while ($("toasts").children.length > 3) $("toasts").firstChild.remove();
  setTimeout(() => t.remove(), 6500);
}
function mdToDom(md) {
  const root = h("div", { class: "pm" }); let ul = null;
  const inline = (text) => { const out = []; text.split(/(\*\*[^*]+\*\*|`[^`]+`)/).forEach((p) => { if (p.startsWith("**")) out.push(h("b", null, p.slice(2, -2))); else if (p.startsWith("`")) out.push(h("code", null, p.slice(1, -1))); else if (p) out.push(p); }); return out; };
  for (const line of md.split("\n")) {
    if (line.startsWith("# ")) { ul = null; root.append(h("h1", null, line.slice(2))); }
    else if (line.startsWith("## ")) { ul = null; root.append(h("h2", null, line.slice(3))); }
    else if (line.startsWith("- ")) { if (!ul) { ul = h("ul"); root.append(ul); } ul.append(h("li", null, inline(line.slice(2)))); }
    else if (line.trim()) { ul = null; root.append(h("p", null, inline(line))); } else ul = null;
  }
  return root;
}
function openDialog(title, body) {
  const dlg = $("dlg"), box = clear($("dlgBody"));
  box.append(h("div", { class: "dlg-head" }, h("h2", { id: "dlgTitle" }, title), h("button", { class: "btn sm close", onclick: () => dlg.close() }, "Close")), body);
  if (!dlg.open) dlg.showModal();
}
async function showPostmortem(id) {
  const r = await send("GET", `/api/incidents/${id}/postmortem`);
  if (!r.text) { toast(r.data?.error || "No post-mortem available", "bad"); return; }
  openDialog(`Post-mortem for ${id}`, h("div", null, mdToDom(r.text), h("div", { class: "actions", style: "margin-top:18px" },
    h("button", { class: "btn sm", onclick: () => navigator.clipboard?.writeText(r.text).then(() => toast("Copied as Markdown", "ok")) }, "Copy as Markdown"))));
}
function showAbout() {
  const step = (n, t, p) => h("li", null, h("span", { class: "num" }, n), h("div", null, h("b", null, t), h("p", null, p)));
  openDialog("How Vigil works", h("div", null,
    h("p", { class: "prose", style: "font-size:16px" }, "Vigil is an agent that does what an on-call engineer does, in seconds, inside limits it cannot override."),
    h("ol", { class: "flowchart" },
      step(1, "Detect", "Prometheus-style alert rules watch error rate, latency, CPU and memory. Alertmanager posts to the FastAPI webhook, and related alerts group into one incident."),
      step(2, "Gather evidence", "Metrics against baseline, pod states, rollout history and recent logs are packaged together. Log lines that try to instruct the agent are quarantined first."),
      step(3, "Diagnose", "Gemini or IBM Granite is asked for the root cause as strict JSON. It follows the dependency graph, so a caller that fails because of a dependency is treated as a symptom. If the model fails, a rule-based reasoner takes over."),
      step(4, "Check limits", "The model only proposes. Plain code checks an action allowlist, that the target exists, a scale ceiling, an availability floor, a cooldown, a rate limit and a confidence floor. Rollbacks always need a human."),
      step(5, "Act", "Only three scoped calls exist: delete one pod, change a replica count, or roll back a deployment, all inside one namespace."),
      step(6, "Verify and report", "The agent waits for the service to stay healthy, then writes the incident record and a post-mortem. If the fix does not hold, it escalates instead of trying again."))));
}

// ------------------------------------------------------------------ wiring
function wire() {
  $("dial").addEventListener("click", (e) => { const b = e.target.closest("button[data-mode]"); if (b) act("/api/mode", { mode: b.dataset.mode }); });
  $("speed").addEventListener("click", (e) => { const b = e.target.closest("button[data-speed]"); if (b) act("/api/speed", { speed: +b.dataset.speed }); });
  $("pause").addEventListener("click", () => act("/api/pause", { paused: !S.config.paused }));
  $("reset").addEventListener("click", () => act("/api/reset", {}, "Cluster reset"));
  $("about").addEventListener("click", showAbout);
  $("auto").addEventListener("click", () => { if (!S.engine) return; S.engine.autopilot = !S.engine.autopilot; renderBar(); toast(S.engine.autopilot ? "Autopilot on: a new failure appears whenever things are calm" : "Autopilot off"); });
  $("breakBtn").addEventListener("click", (e) => { e.stopPropagation(); const m = $("breakMenu"); m.hidden = !m.hidden; $("breakBtn").setAttribute("aria-expanded", String(!m.hidden)); });
  document.addEventListener("click", (e) => { if (!e.target.closest(".break")) closeMenu(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeMenu(); });
  $("dlg").addEventListener("click", (e) => { if (e.target === $("dlg")) $("dlg").close(); });
}

wire();
connect().catch((e) => { $("watch").textContent = "Could not start"; console.error(e); toast(`Could not start: ${e.message}`, "bad"); });
