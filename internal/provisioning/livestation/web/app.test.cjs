"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const live = require("./app.js");

function runtime() {
  return {
    schema_version: live.RUNTIME_SCHEMA,
    state_schema_version: live.LIVE_STATE_SCHEMA,
    expected_origin: "http://127.0.0.1:8081",
    state_endpoint: "/api/v1/state",
    action_endpoint: "/api/v1/actions",
    simulation: false,
    secret_free: true,
    rollback_status: "rollback_unimplemented",
    enrollment_capable: false
  };
}

function state() {
  return {
    schema_version: live.LIVE_STATE_SCHEMA,
    revision: 7,
    simulation: false,
    secret_free: true,
    phase: "commit_intent_recorded",
    instruction: "Execute the approved commit exactly once.",
    safety: {
      simulation: false,
      secret_free: true,
      rollback_status: "rollback_unimplemented",
      enrollment_capable: false
    },
    allowed_actions: ["execute_commit"],
    action_presentations: [{
      action: "execute_commit",
      label: "Execute commit",
      description: "Cross the one-way ownership boundary.",
      classification: "irreversible",
      requires_confirmation: true,
      point_of_no_return: true
    }],
    evidence: []
  };
}

test("accepts only the exact live runtime and state safety boundary", () => {
  assert.equal(live.validateRuntimeConfig(runtime(), "http://127.0.0.1:8081").simulation, false);
  assert.equal(live.validateState(state()).revision, 7);

  const simulatedRuntime = runtime();
  simulatedRuntime.simulation = true;
  assert.throws(() => live.validateRuntimeConfig(simulatedRuntime, "http://127.0.0.1:8081"), /contract rejected/);
  assert.throws(() => live.validateRuntimeConfig(runtime(), "http://127.0.0.1:9999"), /origin/);
  const widenedRuntime = runtime();
  widenedRuntime.unexpected_field = true;
  assert.throws(() => live.validateRuntimeConfig(widenedRuntime, "http://127.0.0.1:8081"), /fields changed/);

  for (const mutate of [
    value => { value.simulation = true; },
    value => { value.secret_free = false; },
    value => { value.safety.rollback_status = "implemented"; },
    value => { value.safety.enrollment_capable = true; }
  ]) {
    const value = state();
    mutate(value);
    assert.throws(() => live.validateState(value), /contract rejected/);
  }
});

test("never accepts an enrollment-ready action or phase", () => {
  const offered = state();
  offered.allowed_actions = ["mark_enrollment_ready"];
  offered.action_presentations[0].action = "mark_enrollment_ready";
  assert.throws(() => live.validateState(offered), /enrollment action/);
  const phase = state();
  phase.phase = "enrollment_ready";
  assert.throws(() => live.validateState(phase), /lifecycle is prohibited/);
});

test("constructs an optimistic action and confirms irreversible metadata", () => {
  assert.deepEqual(live.buildActionRequest("execute_commit", 7), {
    action: "execute_commit",
    expected_revision: 7
  });
  assert.equal(live.requiresExplicitConfirmation(state().action_presentations[0]), true);
  const unsafe = state();
  unsafe.action_presentations[0].requires_confirmation = false;
  unsafe.action_presentations[0].point_of_no_return = false;
  assert.throws(() => live.validateState(unsafe), /confirmation metadata/);
  assert.throws(() => live.buildActionRequest("mark_enrollment_ready", 7));
  assert.throws(() => live.buildActionRequest("execute_commit", 0));
});

const fs = require("node:fs");
const path = require("node:path");
const observedAt = "2026-09-16T12:01:00Z";
const updatedAt = "2026-09-16T11:00:00Z";
const operationNames = [
  "program_customer_key_and_eeprom", "cold_power_cycle", "owned_readback",
  "test_owned_recovery", "post_recovery_readback", "test_negative_boot", "test_root_integrity"
];
const operationStatuses = [
  "intent_recorded", "succeeded", "failed", "uncertain", "confirmed_applied", "confirmed_not_applied", "not_recorded"
];
function human(value) {
  return value[0].toUpperCase() + value.slice(1).replace(/_/g, " ");
}
function observerRuntime() {
  return {
    schema_version: live.OBSERVATION_RUNTIME_SCHEMA,
    state_schema_version: live.OBSERVATION_STATE_SCHEMA,
    expected_origin: "http://127.0.0.1:8081",
    state_endpoint: "/api/v1/state",
    simulation: false,
    read_only: true,
    enrollment_capable: false,
    refresh_interval_seconds: 5
  };
}
function observation() {
  return {
    schema_version: live.OBSERVATION_STATE_SCHEMA,
    station_id: "station-one", lane_id: "lane-one", transaction_id: "transaction-private",
    read_status: "current", read_detail: "Read the recorded transaction successfully.", stale: false,
    last_attempted_read: observedAt, last_successful_read: observedAt,
    local_ports: {
      observed_at: observedAt, detail: "Presence only; ports do not authenticate a device.",
      usb: { path: "/sys/bus/usb/devices/1-1", status: "absent" },
      uart: { path: "/dev/serial/by-id/test", status: "present" }
    },
    unresolved_conditions: ["Operation outcome requires reconciliation.", "Fleet admission has not been evaluated."],
    next_action: "Ask the authorized operator to reconcile; do not repeat the operation.",
    snapshot: {
      id: "transaction-private", resource_version: 9, status: "reconciliation_required",
      status_label: "Reconciliation required", updated_at: updatedAt,
      asset_id: "asset-private", intended_logical_id: "logical-private", profile_id: "pi5-profile",
      claim_history: [],
      recorded_prestate: {
        fingerprint: "fingerprint-private", customer_key_hash: "prestate-key-private",
        observation_digest: "prestate-observation-private", bound_at: updatedAt, fence_epoch: 1
      },
      expected: {
        customer_key_hash: "expected-key-private", prestate_customer_key_hash: "expected-prestate-private",
        bundle_digest: "bundle-private", policy_digest: "policy-private", transaction_digest: "transaction-digest-private"
      },
      operations: operationNames.map((operation, index) => ({
        sequence: index + 1, operation, label: human(operation),
        status: operationStatuses[index], status_label: human(operationStatuses[index]),
        ...(operationStatuses[index] === "not_recorded" ? {} : {
          record_id: "operation-private-" + index, intent_at: updatedAt,
          intent_audit_receipt_id: "receipt-private-" + index, input_digest: "input-private-" + index
        })
      })),
      hardware: { customer_key: "unknown", secure_boot: "unknown", jtag: "unknown", eeprom_write_protection: "unknown" },
      evidence_basis: "coordinator_recorded", fleet_admission: "unevaluated"
    }
  };
}
function rejectedObservation(status) {
  const value = observation();
  value.read_status = status;
  value.read_detail = "Transaction read rejected: " + status;
  value.next_action = "Resolve the authority read failure.";
  delete value.snapshot;
  delete value.last_successful_read;
  return value;
}
function response(value, status = 200) {
  return { ok: status >= 200 && status < 300, status, headers: { get: () => "application/json" }, json: async () => value };
}
class Element {
  constructor(tag = "div") {
    this.tagName = tag;
    this.children = [];
    this.listeners = {};
    this.dataset = {};
    this.hidden = false;
    this.disabled = false;
    this.ownText = "";
  }
  set textContent(value) { this.ownText = String(value); this.children = []; }
  get textContent() { return this.ownText + this.children.map(child => child.textContent).join(" "); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.ownText = ""; this.children = children; }
  addEventListener(name, listener) { this.listeners[name] = listener; }
}
function visibleText(element) {
  if (element.hidden) return "";
  const children = element.tagName === "details" ? element.children.slice(0, 1) : element.children;
  return element.ownText + " " + children.map(visibleText).join(" ");
}
function browser(responses) {
  const elements = new Map();
  const html = fs.readFileSync(path.join(__dirname, "index.html"), "utf8");
  for (const match of html.matchAll(/<([a-z][a-z0-9]*)\b[^>]*\bid="([^"]+)"[^>]*>/g)) {
    const element = new Element(match[1]);
    element.hidden = match[0].includes(" hidden");
    elements.set(match[2], element);
  }
  const calls = [];
  const timers = new Map();
  const listeners = {};
  let nextTimer = 1;
  const windowObject = {
    document: {
      createElement: tag => new Element(tag),
      getElementById(id) {
        assert.ok(elements.has(id), "Unknown element: " + id);
        return elements.get(id);
      }
    },
    location: { origin: "http://127.0.0.1:8081" },
    fetch: async (url, options) => {
      calls.push({ url, options });
      assert.ok(responses.length, "Unexpected fetch: " + url);
      const next = responses.shift();
      return typeof next === "function" ? next() : next;
    },
    setTimeout: (callback, milliseconds) => {
      const id = nextTimer++;
      timers.set(id, { callback, milliseconds });
      return id;
    },
    clearTimeout: id => timers.delete(id),
    addEventListener: (name, callback) => { listeners[name] = callback; }
  };
  return { windowObject, elements, calls, timers, listeners };
}

test("observer runtime is an exact read-only contract selected independently from foundation", () => {
  assert.equal(live.validateRuntimeConfig(observerRuntime(), "http://127.0.0.1:8081").read_only, true);
  assert.equal(live.validateState(observation(), live.OBSERVATION_STATE_SCHEMA).snapshot.resource_version, 9);
  assert.throws(() => live.validateState(observation()), /unsupported state schema/);
  assert.throws(() => live.validateState(state(), live.OBSERVATION_STATE_SCHEMA), /unsupported observation state schema/);
  for (const mutate of [
    value => { value.action_endpoint = "/api/v1/actions"; },
    value => { value.read_only = false; },
    value => { value.enrollment_capable = true; },
    value => { value.simulation = true; },
    value => { value.refresh_interval_seconds = 1; },
    value => { value.state_schema_version = live.LIVE_STATE_SCHEMA; }
  ]) {
    const value = observerRuntime();
    mutate(value);
    assert.throws(() => live.validateRuntimeConfig(value, "http://127.0.0.1:8081"), /contract rejected/);
  }
});

test("observer validation rejects mismatched, misleading, and uncleared snapshots", () => {
  for (const status of ["created", "claimed", "target_bound", "commit_approved", "mutation_in_progress", "reconciliation_required", "reconciled", "security_applied", "aborted", "quarantined"]) {
    const value = observation();
    value.snapshot.status = status;
    assert.equal(live.validateObservationState(value).snapshot.status, status);
  }
  for (const status of ["denied", "not_found", "invalid_response"]) {
    assert.equal(live.validateObservationState(rejectedObservation(status)).snapshot, undefined);
  }
  for (const mutate of [
    value => { value.snapshot.id = "different-transaction"; },
    value => { value.snapshot.fleet_admission = "admitted"; },
    value => { value.snapshot.evidence_basis = "independently_verified"; },
    value => { value.snapshot.hardware.secure_boot = "enabled"; },
    value => { value.snapshot.operations.reverse(); },
    value => { value.snapshot.operations[0].status = "complete"; },
    value => { value.snapshot.claim_history = {}; },
    value => { value.snapshot.active_claim = { status: true }; },
    value => { value.read_status = "denied"; },
    value => { value.stale = true; },
    value => { value.last_successful_read = "invalid"; },
    value => { delete value.snapshot; }
  ]) {
    const value = observation();
    mutate(value);
    assert.throws(() => live.validateObservationState(value), /contract rejected/);
  }
});

test("observer renders real progress, distinct times, unknown hardware, and collapsed reference details", async () => {
  const env = browser([response(observerRuntime()), response(observation())]);
  await live.start(env.windowObject);
  const get = id => env.elements.get(id);
  assert.equal(get("phase-title").textContent, "Reconciliation required");
  assert.equal(get("operation-list").children.length, 7);
  for (const status of operationStatuses) assert.match(get("operation-list").textContent, new RegExp(human(status)));
  assert.match(get("target-facts").textContent, /asset-private/);
  assert.match(get("target-facts").textContent, /Current secure boot Unknown/);
  assert.match(get("observation-time-facts").textContent, /Authority updated 2026-09-16T11:00:00.000Z/);
  assert.match(get("observation-time-facts").textContent, /Last successfully checked 2026-09-16T12:01:00.000Z/);
  assert.match(get("diagnostic-facts").textContent, /Recorded prestate customer key prestate-key-private/);
  assert.match(get("diagnostic-facts").textContent, /Expected customer key expected-key-private/);
  assert.equal(get("observation-diagnostics").tagName, "details");
  assert.equal(get("action-panel").hidden, true);
  assert.equal(get("actions").children.length, 0);
  assert.doesNotMatch(visibleText(get("evidence-list")), /receipt-private|input-private/);
  assert.match(get("evidence-list").textContent, /receipt-private/);
  assert.doesNotMatch(get("safety-title").textContent, /rollback/i);
  assert.match(get("safety-title").textContent, /Fleet admission has not been evaluated/);
  assert.deepEqual(env.calls.map(call => call.options.method), ["GET", "GET"]);
  assert.deepEqual([...env.timers.values()].map(timer => timer.milliseconds), [5000]);
});

test("authority outages retain stale recorded state and reconnection replaces it", async () => {
  const stale = observation();
  stale.read_status = "unavailable";
  stale.stale = true;
  stale.read_detail = "Authority unavailable.";
  stale.last_attempted_read = "2026-09-16T12:02:00Z";
  const current = observation();
  current.snapshot.resource_version = 10;
  current.snapshot.status = "security_applied";
  current.snapshot.status_label = "Development security applied";
  const env = browser([response(observerRuntime()), response(observation()), response(stale), response(current)]);
  const controller = await live.start(env.windowObject);
  await controller.reload();
  assert.equal(env.elements.get("connection-status").dataset.status, "stale");
  assert.match(env.elements.get("connection-status").textContent, /STALE/);
  assert.match(env.elements.get("target-facts").textContent, /asset-private/);
  assert.match(env.elements.get("observation-time-facts").textContent, /12:01:00.000Z/);
  await controller.reload();
  assert.equal(env.elements.get("connection-status").dataset.status, "ok");
  assert.equal(env.elements.get("revision").textContent, "Resource version 10");
  assert.equal(env.elements.get("phase-title").textContent, "Development security applied");
  assert.match(env.elements.get("transaction-facts").textContent, /Fleet admission Unevaluated/);
});

test("denied, not-found and invalid authority responses clear transaction and evidence details", async () => {
  for (const status of ["denied", "not_found", "invalid_response"]) {
    const env = browser([response(observerRuntime()), response(observation()), response(rejectedObservation(status))]);
    const controller = await live.start(env.windowObject);
    await controller.reload();
    const allText = [...env.elements.values()].map(element => element.textContent).join(" ");
    assert.doesNotMatch(allText, /asset-private|prestate-key-private|expected-key-private|receipt-private|operation-private/);
    assert.equal(env.elements.get("phase-title").textContent, "Transaction status unknown");
    assert.equal(env.elements.get("operation-list").children.length, 1);
    assert.equal(env.elements.get("evidence-count").textContent, "0 records");
    assert.match(env.elements.get("observation-time-facts").textContent, /Last successfully checked Not yet checked/);
    assert.equal(env.elements.get("connection-status").dataset.status, "error");
  }
});

test("browser-to-station outage marks retained view stale; malformed or denied responses clear it", async () => {
  const malformed = observation();
  malformed.snapshot.hardware.jtag = "disabled";
  const invalidJSON = response(null);
  invalidJSON.json = async () => { throw new SyntaxError("Malformed JSON"); };
  for (const invalid of [response(malformed), response({}, 400), response({}, 403), response({}, 404), invalidJSON]) {
    const env = browser([
      response(observerRuntime()), response(observation()),
      () => { throw new Error("Network disconnected"); }, invalid, response(observation())
    ]);
    const controller = await live.start(env.windowObject);
    await controller.reload();
    assert.equal(env.elements.get("connection-status").dataset.status, "stale");
    assert.match(env.elements.get("connection-status").textContent, /Network disconnected/);
    assert.match(env.elements.get("target-facts").textContent, /asset-private/);
    await controller.reload();
    assert.equal(env.elements.get("connection-status").dataset.status, "error");
    assert.doesNotMatch(env.elements.get("diagnostic-facts").textContent, /expected-key-private/);
    assert.equal(env.elements.get("evidence-count").textContent, "0 records");
    await controller.reload();
    assert.equal(env.elements.get("connection-status").dataset.status, "ok");
    assert.match(env.elements.get("target-facts").textContent, /asset-private/);
  }
});

test("fresh page with authority unavailable never substitutes remembered or simulation state", async () => {
  const unavailable = rejectedObservation("unavailable");
  const env = browser([response(observerRuntime()), response(unavailable)]);
  await live.start(env.windowObject);
  assert.equal(env.elements.get("phase-title").textContent, "Transaction status unknown");
  assert.equal(env.elements.get("evidence-count").textContent, "0 records");
  assert.equal(env.elements.get("actions").children.length, 0);
  assert.equal(env.elements.get("connection-status").dataset.status, "error");
});

test("polling waits five seconds after completion and manual refresh never overlaps", async () => {
  let complete;
  const deferred = new Promise(resolve => { complete = resolve; });
  const env = browser([response(observerRuntime()), response(observation()), () => deferred]);
  const controller = await live.start(env.windowObject);
  const scheduled = [...env.timers.values()][0];
  assert.equal(scheduled.milliseconds, 5000);
  const polling = scheduled.callback();
  const manual = env.elements.get("refresh").listeners.click();
  assert.equal(manual, polling);
  await Promise.resolve();
  assert.equal(env.calls.length, 3);
  assert.equal(env.timers.size, 0);
  assert.equal(env.elements.get("refresh").disabled, true);
  complete(response(observation()));
  await polling;
  assert.equal(env.elements.get("refresh").disabled, false);
  assert.deepEqual([...env.timers.values()].map(timer => timer.milliseconds), [5000]);
  env.listeners.pagehide();
  assert.equal(env.timers.size, 0);
  await controller.reload();
  assert.equal(env.calls.length, 3);
});

test("foundation retains its existing renderer and manual refresh behavior", async () => {
  const env = browser([response(runtime()), response(state())]);
  await live.start(env.windowObject);
  assert.equal(env.elements.get("phase-title").textContent, "commit intent recorded");
  assert.equal(env.elements.get("action-panel").hidden, false);
  assert.equal(env.elements.get("actions").children.length, 1);
  assert.equal(env.elements.get("operation-panel").hidden, true);
  assert.equal(env.timers.size, 0);
});

test("approval and lease references remain visible before operation intent exists", async () => {
  const value = observation();
  value.snapshot.operations = value.snapshot.operations.map(operation => ({
    sequence: operation.sequence, operation: operation.operation, label: operation.label,
    status: "not_recorded", status_label: "Not recorded"
  }));
  value.snapshot.approval = {
    id: "approval-private", approver_id: "approver-private", transaction_digest: "transaction-digest-private",
    plan_digest: "plan-private", station_id: "station-one", lane_id: "lane-one", fence_epoch: 3,
    target_fingerprint: "fingerprint-private", audit_receipt_id: "approval-receipt-private",
    approved_at: updatedAt, expires_at: observedAt, allowed_operations: operationNames,
    release: {
      expected_eeprom_digest: "eeprom-private", expected_boot_image_digest: "boot-image-private",
      expected_customer_key_hash: "expected-key-private", signed_release_manifest_digest: "manifest-private",
      lane_guard_package_digest: "lane-package-private", compiled_artifact_set_digest: "compiled-private"
    }
  };
  value.snapshot.expected.release = value.snapshot.approval.release;
  value.snapshot.active_claim = {
    id: "claim-private", station_id: "station-one", lane_id: "lane-one", status: "active",
    acquired_at: updatedAt, expires_at: observedAt
  };
  const env = browser([response(observerRuntime()), response(value)]);
  await live.start(env.windowObject);
  assert.equal(env.elements.get("evidence-count").textContent, "1 record");
  assert.match(env.elements.get("evidence-list").textContent, /Commit approval/);
  assert.match(env.elements.get("evidence-list").textContent, /approval-receipt-private/);
  assert.doesNotMatch(visibleText(env.elements.get("evidence-list")), /approval-receipt-private/);
  assert.match(env.elements.get("diagnostic-facts").textContent, /Claim lease expires 2026-09-16T12:01:00Z/);
  assert.match(env.elements.get("transaction-facts").textContent, /Recorded claim status active/);
});

test("back-forward cache restoration refreshes stale state and resumes polling", async () => {
  const refreshed = observation();
  refreshed.snapshot.resource_version = 11;
  const env = browser([response(observerRuntime()), response(observation()), response(refreshed)]);
  const controller = await live.start(env.windowObject);
  env.listeners.pagehide();
  assert.equal(env.timers.size, 0);
  env.listeners.pageshow({ persisted: true });
  assert.equal(env.elements.get("connection-status").dataset.status, "stale");
  await controller.reload();
  assert.equal(env.elements.get("revision").textContent, "Resource version 11");
  assert.equal(env.elements.get("connection-status").dataset.status, "ok");
  assert.deepEqual([...env.timers.values()].map(timer => timer.milliseconds), [5000]);
});
