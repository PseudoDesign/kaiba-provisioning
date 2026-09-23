(function (root, factory) {
  "use strict";
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.KaibaGuidedCampaign = api;
})(typeof globalThis === "undefined" ? this : globalThis, function () {
  "use strict";
  const RUNTIME = "provisioning.kaiba.network/station-campaign-runtime/v1alpha1";
  const STATE = "kaiba.station-campaign-state/v1alpha1";
  const REPORT = "kaiba.station-campaign-report/v1alpha1";
  const ACTIONS = { ready: "begin", running: "pause", awaiting_input: "submit", paused: "continue", reconciliation_required: "reconcile", blocked: null, quarantined: null, completed: null };
  function reject() { const e = new Error("The campaign response could not be verified."); e.clear = true; throw e; }
  function shape(v, keys, optional) {
    if (!v || typeof v !== "object" || Array.isArray(v)) reject();
    if (keys.some(k => !(k in v)) || Object.keys(v).some(k => !keys.includes(k) && !(optional || []).includes(k))) reject();
  }
  function label(v) { if (typeof v !== "string" || v.length > 512 || /[\u0000-\u001f]/.test(v)) reject(); }
  function id(v) { if (typeof v !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(v)) reject(); }
  function digest(v) { if (typeof v !== "string" || !/^sha256:[a-f0-9]{64}$/.test(v)) reject(); }
  function choice(v) { shape(v, ["value", "label"]); id(v.value); label(v.label); }
  function validateRuntime(v, origin) {
    shape(v, ["schema_version", "state_schema_version", "expected_origin", "state_endpoint", "action_endpoint", "report_endpoint", "session_token", "refresh_interval_seconds", "production_enrollment"]);
    if (v.schema_version !== RUNTIME || v.state_schema_version !== STATE || v.expected_origin !== origin || v.state_endpoint !== "/api/v1/state" || v.action_endpoint !== "/api/v1/actions" || v.report_endpoint !== "/api/v1/report" || v.refresh_interval_seconds !== 2 || v.production_enrollment !== false || !/^[a-f0-9]{64}$/.test(v.session_token)) reject();
    return v;
  }
  function validateState(v) {
    shape(v, ["schema_version", "campaign_id", "plan_digest", "revision", "mode", "device_label", "profile_label", "status", "step_id", "step_number", "step_count", "title", "instruction", "output", "actions", "updated_at", "production_enrollment", "hardware_qualified"], ["input"]);
    if (v.schema_version !== STATE || !["development", "software_rehearsal"].includes(v.mode) || v.production_enrollment !== false || v.hardware_qualified !== false || !Object.prototype.hasOwnProperty.call(ACTIONS, v.status) || !Number.isSafeInteger(v.revision) || v.revision < 1) reject();
    id(v.campaign_id); digest(v.plan_digest);
    if (v.step_id !== "") id(v.step_id);
    ["device_label", "profile_label", "title", "instruction", "output"].forEach(k => label(v[k]));
    if (!Number.isInteger(v.step_number) || !Number.isInteger(v.step_count) || v.step_number < 1 || v.step_number > v.step_count || v.step_count > 32 || !Number.isFinite(Date.parse(v.updated_at))) reject();
    if (!Array.isArray(v.actions) || v.actions.length > 1) reject();
    v.actions.forEach(c => { choice(c); if (!ACTIONS[v.status] || c.value !== ACTIONS[v.status]) reject(); });
    if (v.input !== undefined) {
      shape(v.input, ["label", "choices"]); label(v.input.label);
      if (v.status !== "awaiting_input" || !Array.isArray(v.input.choices) || v.input.choices.length < 1 || v.input.choices.length > 6) reject();
      v.input.choices.forEach(choice);
      if (new Set(v.input.choices.map(c => c.value)).size !== v.input.choices.length) reject();
    }
    if (v.status === "awaiting_input" && !v.input) reject();
    return v;
  }
  function prepare(document) {
    Array.from(document.getElementById("station-main").children).forEach(c => { c.hidden = c.id !== "campaign-screen"; });
    document.getElementById("station-label").textContent = "Guided development campaign";
    document.getElementById("station-title").textContent = "Kaiba Station";
    document.getElementById("mode-marker").textContent = "Development";
    document.getElementById("station-footer").textContent = "Production admission remains unevaluated";
  }
  function render(document, state, active, stale) {
    const text = (id, value) => { document.getElementById(id).textContent = value; };
    text("campaign-device", state ? state.device_label + " · " + state.profile_label : "Waiting for the configured device");
    text("campaign-progress", state ? "Step " + state.step_number + " of " + state.step_count : "Connecting");
    text("campaign-title", state ? state.title : "Connecting to the station");
    text("campaign-instruction", state ? state.instruction : "The station will retrieve the saved campaign.");
    text("campaign-output", state ? state.output : "No result available.");
    text("mode-marker", state && state.mode === "software_rehearsal" ? "Software rehearsal" : "Development");
    const actions = document.getElementById("campaign-actions"); actions.replaceChildren();
    const input = document.getElementById("campaign-input"); input.replaceChildren();
    if (state && state.input) {
      const labelElement = document.createElement("label"); labelElement.textContent = state.input.label; labelElement.htmlFor = "campaign-choice";
      const select = document.createElement("select"); select.id = "campaign-choice";
      const placeholder = document.createElement("option"); placeholder.value = ""; placeholder.textContent = "Select a response"; select.append(placeholder);
      state.input.choices.forEach(c => { const o = document.createElement("option"); o.value = c.value; o.textContent = c.label; select.append(o); });
      select.disabled = active || stale; input.append(labelElement, select);
    }
    if (state) state.actions.forEach(c => {
      const button = document.createElement("button"); button.type = "button"; button.textContent = c.label; button.dataset.action = c.value;
      button.disabled = active || stale; actions.append(button);
    });
    document.getElementById("campaign-export").disabled = active || stale || !state;
    document.getElementById("campaign-refresh").disabled = active;
  }
  async function read(response) {
    if (!response.ok) { const e = new Error(response.status === 409 ? "Progress changed. Refresh to check the recorded result." : "The station could not confirm current progress."); e.status = response.status; e.clear = ![409, 503, 504].includes(response.status); throw e; }
    if ((response.headers.get("Content-Type") || "").split(";", 1)[0].trim().toLowerCase() !== "application/json") reject();
    try { return await response.json(); } catch (_) { reject(); }
  }
  async function start(win, runtime) {
    validateRuntime(runtime, win.location.origin);
    const d = win.document; prepare(d);
    let state = null, pending = null, timer = null, stopped = false, stale = true, renderedInput = "";
    const status = (message, kind) => { const el = d.getElementById("campaign-connection"); el.textContent = message; el.dataset.status = kind; };
    const options = method => ({ method, credentials: "same-origin", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer", headers: { "X-Kaiba-Campaign-Token": runtime.session_token } });
    function accept(next) {
      validateState(next);
      if (state && (state.campaign_id !== next.campaign_id || state.plan_digest !== next.plan_digest || next.revision < state.revision)) reject();
      state = next; stale = false;
      status("Progress checked " + new Date().toLocaleTimeString() + ".", "ok");
    }
    function renderCurrent(active) {
      const key = state && state.input ? state.campaign_id + ":" + state.step_id + ":" + JSON.stringify(state.input) : "";
      const existing = d.getElementById("campaign-choice");
      const selected = existing && key === renderedInput ? existing.value : "";
      render(d, state, active, stale);
      const select = d.getElementById("campaign-choice");
      if (select && state.input.choices.some(c => c.value === selected)) select.value = selected;
      renderedInput = key;
      Array.from(d.getElementById("campaign-actions").children).forEach(button => button.addEventListener("click", () => submit(button.dataset.action)));
    }
    function run(operation) {
      if (pending) return pending;
      if (stopped) return Promise.resolve();
      if (timer !== null) win.clearTimeout(timer);
      // Capture input before changing the form while the request is in flight.
      pending = Promise.resolve().then(operation).catch(async error => {
        stale = true;
        if (error.clear) state = null;
        status((state ? "Last recorded result — " : "Status unavailable — ") + error.message, "error");
        // A restarted kiosk issues a new session capability. Reacquire it,
        // then read progress on the next poll; never replay the rejected POST.
        if (error.status === 403) {
          try { runtime = validateRuntime(await read(await win.fetch("/runtime-config.json", options("GET"))), win.location.origin); }
          catch (_) { state = null; }
        }
      }).finally(() => {
        pending = null; renderCurrent(false);
        if (!stopped) timer = win.setTimeout(refresh, runtime.refresh_interval_seconds * 1000);
      });
      renderCurrent(true);
      return pending;
    }
    function refresh() { return run(async () => accept(await read(await win.fetch(runtime.state_endpoint, options("GET"))))); }
    function submit(action) {
      if (pending || stale || !state) return Promise.resolve();
      const select = d.getElementById("campaign-choice");
      const input = action === "submit" && select ? select.value : "";
      if (action === "submit" && !state.input.choices.some(c => c.value === input)) { status("Select the response needed to continue.", "error"); return Promise.resolve(); }
      const request = { request_id: win.crypto.randomUUID(), expected_revision: state.revision, action, input };
      return run(async () => {
        const o = options("POST"); o.headers["Content-Type"] = "application/json"; o.body = JSON.stringify(request);
        accept(await read(await win.fetch(runtime.action_endpoint, o)));
      });
    }
    function exportReport() {
      if (!state || stale) return Promise.resolve();
      return run(async () => {
        const report = await read(await win.fetch(runtime.report_endpoint, options("GET")));
        if (!report || report.schema_version !== REPORT || report.evidence_basis !== "packet_executor_records_not_independent_audit") reject();
        validateState(report.state);
        if (report.state.campaign_id !== state.campaign_id || report.state.plan_digest !== state.plan_digest) reject();
        const url = win.URL.createObjectURL(new win.Blob([JSON.stringify(report, null, 2) + "\n"], { type: "application/json" }));
        const link = d.createElement("a"); link.href = url; link.download = "kaiba-campaign-report.json"; link.click(); win.URL.revokeObjectURL(url);
      });
    }
    d.getElementById("campaign-refresh").addEventListener("click", refresh);
    d.getElementById("campaign-export").addEventListener("click", exportReport);
    function stop() { stopped = true; if (timer !== null) win.clearTimeout(timer); }
    win.addEventListener("pagehide", stop);
    win.addEventListener("pageshow", event => { if (event.persisted) { stopped = false; stale = true; renderCurrent(false); refresh(); } });
    await refresh();
    return { refresh, submit, exportReport, stop };
  }
  return { RUNTIME, STATE, validateRuntime, validateState, render, start };
});
