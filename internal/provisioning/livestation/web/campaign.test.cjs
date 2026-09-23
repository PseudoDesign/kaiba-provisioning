"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const guided = require("./campaign.js");
const live = require("./app.js");

function state(status = "ready", revision = 1) {
  const actions = { ready: "begin", running: "pause", awaiting_input: "submit", paused: "continue", reconciliation_required: "reconcile" };
  const s = { schema_version: guided.STATE, campaign_id: "campaign-1", plan_digest: "sha256:" + "a".repeat(64), revision,
    mode: "development", device_label: "Development Pi", profile_label: "Isolated enrollment", status,
    step_id: "prepare", step_number: 1, step_count: 3, title: "Prepare the device", instruction: "Keep the device connected.", output: "Device connection verified.",
    actions: actions[status] ? [{ value: actions[status], label: "Continue" }] : [], updated_at: "2026-09-22T23:00:00Z", production_enrollment: false, hardware_qualified: false };
  if (status === "awaiting_input") s.input = { label: "Confirm the cable connection", choices: [{ value: "connected", label: "Connected" }] };
  return s;
}
function runtime() { return { schema_version: guided.RUNTIME, state_schema_version: guided.STATE, expected_origin: "http://127.0.0.1:8081", state_endpoint: "/api/v1/state", action_endpoint: "/api/v1/actions", report_endpoint: "/api/v1/report", session_token: "b".repeat(64), refresh_interval_seconds: 2, production_enrollment: false }; }
class Element {
  constructor(tag = "div") { this.tagName = tag; this.children = []; this.dataset = {}; this.events = {}; this.hidden = false; this.disabled = false; this.value = ""; this.textContent = ""; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  addEventListener(name, fn) { this.events[name] = fn; }
  click() { if (this.events.click) return this.events.click(); }
}
function environment(fetch) {
  const root = new Element();
  const add = (parent, id) => { const el = new Element(); el.id = id; parent.append(el); return el; };
  const main = add(root, "station-main"); add(main, "old-diagnostics"); const screen = add(main, "campaign-screen");
  ["campaign-device", "campaign-progress", "campaign-title", "campaign-instruction", "campaign-output", "campaign-actions", "campaign-input", "campaign-connection", "campaign-export", "campaign-refresh"].forEach(id => add(screen, id));
  ["station-label", "station-title", "mode-marker", "station-footer"].forEach(id => add(root, id));
  function find(el, id) { if (el.id === id) return el; for (const c of el.children) { const f = find(c, id); if (f) return f; } return null; }
  const timers = new Map(), events = {}; let timerID = 0, uuid = 0;
  return { document: { getElementById: id => find(root, id), createElement: tag => new Element(tag) }, location: { origin: runtime().expected_origin }, fetch,
    crypto: { randomUUID: () => "tap-" + (++uuid) }, setTimeout(fn, delay) { const id = ++timerID; timers.set(id, { fn, delay }); return id; }, clearTimeout(id) { timers.delete(id); }, addEventListener(name, fn) { events[name] = fn; }, timers, events,
    URL: { createObjectURL: () => "blob:public-report", revokeObjectURL() {} }, Blob: class { constructor(parts) { this.parts = parts; } } };
}
function response(value, status = 200) { return { ok: status === 200, status, headers: { get: () => "application/json" }, json: async () => value }; }
function deferred() { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; }

test("campaign is an explicit runtime with bounded state and no admission claims", () => {
  assert.equal(live.validateRuntimeConfig(runtime(), runtime().expected_origin).schema_version, guided.RUNTIME);
  for (const s of ["ready", "running", "awaiting_input", "paused", "reconciliation_required", "blocked", "quarantined", "completed"]) assert.equal(guided.validateState(state(s)).status, s);
  for (const mutate of [s => s.production_enrollment = true, s => s.hardware_qualified = true, s => s.status = "active", s => s.actions.push({ value: "arbitrary_command", label: "Run" }), s => s.private_key = "secret", s => s.step_number = 4]) { const s = state(); mutate(s); assert.throws(() => guided.validateState(s)); }
  const config = runtime(); config.action_endpoint = "https://elsewhere/actions"; assert.throws(() => guided.validateRuntime(config, runtime().expected_origin));
});
test("touch view shows input and result and preserves selection through polling", async () => {
  const win = environment(async () => response(state("awaiting_input"))); const client = await guided.start(win, runtime()); const d = win.document;
  assert.equal(d.getElementById("old-diagnostics").hidden, true);
  assert.equal(d.getElementById("campaign-screen").hidden, false);
  assert.equal(d.getElementById("campaign-title").textContent, "Prepare the device");
  assert.equal(d.getElementById("campaign-output").textContent, "Device connection verified.");
  assert.equal(d.getElementById("mode-marker").textContent, "Development");
  d.getElementById("campaign-choice").value = "connected";
  await client.refresh(); assert.equal(d.getElementById("campaign-choice").value, "connected");
  assert.equal(win.timers.size, 1); assert.equal([...win.timers.values()][0].delay, 2000); client.stop();
});
test("automatic polling and duplicate taps never overlap or repeat a POST", async () => {
  const inFlight = deferred(), calls = []; const win = environment(async (url, options) => { calls.push({ url, options }); return options.method === "POST" ? inFlight.promise : response(state()); });
  const client = await guided.start(win, runtime());
  const first = client.submit("begin"); const duplicate = client.submit("begin"); const refresh = client.refresh();
  await Promise.resolve(); assert.equal(calls.filter(c => c.options.method === "POST").length, 1); assert.equal(win.timers.size, 0);
  assert.equal(win.document.getElementById("campaign-actions").children[0].disabled, true);
  inFlight.resolve(response(state("running", 2))); await Promise.all([first, duplicate, refresh]);
  const sent = JSON.parse(calls[1].options.body); assert.deepEqual(sent, { request_id: "tap-1", expected_revision: 1, action: "begin", input: "" });
  assert.equal(calls[1].options.headers["X-Kaiba-Campaign-Token"], runtime().session_token); client.stop();
});
test("lost action response retains a stale view and recovers by GET only", async () => {
  const calls = []; let s = state(); const win = environment(async (url, o) => { calls.push(o.method); if (o.method === "POST") { s = state("awaiting_input", 3); throw new Error("Connection lost"); } return response(s); });
  const client = await guided.start(win, runtime()); await client.submit("begin");
  assert.match(win.document.getElementById("campaign-connection").textContent, /Last recorded result/);
  assert.equal(win.document.getElementById("campaign-actions").children[0].disabled, true);
  await client.submit("begin"); assert.equal(calls.filter(v => v === "POST").length, 1);
  await client.refresh(); assert.equal(win.document.getElementById("campaign-choice").disabled, false);
  const reloaded = environment(win.fetch); const reopened = await guided.start(reloaded, runtime());
  assert.equal(reloaded.document.getElementById("campaign-output").textContent, s.output); assert.equal(calls.filter(v => v === "POST").length, 1); client.stop(); reopened.stop();
});
test("denied, malformed and wrong-campaign state clears details and action controls", async () => {
  for (const fault of [() => response({}, 403), () => response({ ...state(), private_key: "secret" }), () => response({ ...state(), campaign_id: "other" }), () => response({}, 502)]) {
    let fetch = async () => response(state()); const win = environment((...args) => fetch(...args)); const client = await guided.start(win, runtime()); fetch = fault; await client.refresh();
    assert.equal(win.document.getElementById("campaign-actions").children.length, 0); assert.equal(win.document.getElementById("campaign-output").textContent, "No result available."); assert.equal(win.document.getElementById("campaign-export").disabled, true); client.stop();
  }
});
test("required input is validated locally and report export makes no action call", async () => {
  const calls = [], win = environment(async (url, o) => { calls.push({ url, o }); if (url.endsWith("report")) return response({ schema_version: "kaiba.station-campaign-report/v1alpha1", evidence_basis: "packet_executor_records_not_independent_audit", state: state("awaiting_input") }); return response(state("awaiting_input")); });
  const client = await guided.start(win, runtime()); await client.submit("submit"); assert.equal(calls.length, 1);
  await client.exportReport(); assert.equal(calls[1].o.method, "GET"); assert.equal(calls[1].url, "/api/v1/report");
  win.document.getElementById("campaign-choice").value = "connected"; await client.submit("submit"); assert.equal(JSON.parse(calls[2].o.body).input, "connected");
  win.events.pagehide(); assert.equal(win.timers.size, 0);
});
test("kiosk restart refreshes the session token without replaying an action", async () => {
  const updated = { ...runtime(), session_token: "c".repeat(64) }, posts = [];
  const win = environment(async (url, o) => {
    if (url === "/runtime-config.json") return response(updated);
    if (o.method === "POST") {
      posts.push(o);
      return o.headers["X-Kaiba-Campaign-Token"] === updated.session_token ? response(state("running", 2)) : response({}, 403);
    }
    return response(state());
  });
  const client = await guided.start(win, runtime());
  await client.submit("begin");
  assert.equal(posts.length, 1);
  assert.equal(win.document.getElementById("campaign-actions").children.length, 0);
  await client.refresh();
  assert.equal(posts.length, 1);
  await client.submit("begin");
  assert.equal(posts.length, 2);
  assert.equal(posts[1].headers["X-Kaiba-Campaign-Token"], updated.session_token);
  client.stop();
});
