(function (root, factory) {
  "use strict";
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.KaibaLiveStation = api;
  if (root.document) {
    root.addEventListener("DOMContentLoaded", function () {
      api.start(root).catch(function (error) {
        api.showFatal(root.document, error);
      });
    });
  }
})(typeof globalThis === "undefined" ? this : globalThis, function () {
  "use strict";

  const guided = typeof module === "object" && module.exports ? require("./campaign.js") : globalThis.KaibaGuidedCampaign;
  const RUNTIME_SCHEMA = "provisioning.kaiba.network/station-live-runtime/v1alpha1";
  const LIVE_STATE_SCHEMA = "provisioning.kaiba.network/station-live-state/v1alpha1";
  const OBSERVATION_RUNTIME_SCHEMA = "provisioning.kaiba.network/station-observation-runtime/v1alpha1";
  const OBSERVATION_STATE_SCHEMA = "provisioning.kaiba.network/station-observation-state/v1alpha1";
  const OBSERVATION_OPERATIONS = [
    "program_customer_key_and_eeprom", "cold_power_cycle", "owned_readback",
    "test_owned_recovery", "post_recovery_readback", "test_negative_boot", "test_root_integrity"
  ];
  const OBSERVATION_STATUSES = new Set([
    "created", "claimed", "target_bound", "commit_approved", "mutation_in_progress",
    "reconciliation_required", "reconciled", "security_applied", "aborted", "quarantined"
  ]);
  const OPERATION_STATUSES = new Set([
    "not_recorded", "intent_recorded", "succeeded", "failed", "uncertain",
    "confirmed_applied", "confirmed_not_applied"
  ]);
  const READ_STATUSES = new Set(["current", "unavailable", "denied", "not_found", "invalid_response"]);
  const ROLLBACK_STATUS = "rollback_unimplemented";
  const FORBIDDEN_ACTION = "mark_enrollment_ready";
  const SUPPORTED_ACTIONS = new Set([
    "run_station_admission",
    "create_transaction",
    "attach_target",
    "run_fresh_qualification",
    "prepare_transaction",
    "request_commit_approval",
    "record_commit_intent",
    "execute_commit",
    "reconcile_commit",
    "confirm_signed_boot",
    "run_owned_readback",
    "test_owned_recovery",
    "rerun_owned_readback",
    "test_negative_boot",
    "test_root_integrity",
    "reconcile_audit",
    "mark_security_applied",
    "export_redacted",
    "reset"
  ]);

  function fail(message) {
    const error = new Error("Live station contract rejected: " + message);
    error.clearObservation = true;
    throw error;
  }

  function object(value, label) {
    if (!value || typeof value !== "object" || Array.isArray(value)) fail(label + " must be an object");
    return value;
  }

  function text(value, label) {
    if (typeof value !== "string" || value.length === 0) fail(label + " must be a non-empty string");
    return value;
  }

  function exactKeys(value, expected, label) {
    const actual = Object.keys(value).sort();
    const wanted = expected.slice().sort();
    if (actual.length !== wanted.length || actual.some(function (key, index) { return key !== wanted[index]; })) {
      fail(label + " fields changed");
    }
  }

  function validateRuntimeConfig(value, browserOrigin) {
    const config = object(value, "runtime config");
    if (config.schema_version === guided.RUNTIME) return guided.validateRuntime(config, browserOrigin);
    if (config.schema_version === OBSERVATION_RUNTIME_SCHEMA) return validateObservationRuntime(config, browserOrigin);
    exactKeys(config, [
      "schema_version", "state_schema_version", "expected_origin", "state_endpoint",
      "action_endpoint", "simulation", "secret_free", "rollback_status", "enrollment_capable"
    ], "runtime config");
    if (config.schema_version !== RUNTIME_SCHEMA) fail("unsupported runtime schema");
    if (config.state_schema_version !== LIVE_STATE_SCHEMA) fail("unsupported live state schema");
    if (config.expected_origin !== browserOrigin) fail("browser origin does not match the station origin");
    if (config.state_endpoint !== "/api/v1/state" || config.action_endpoint !== "/api/v1/actions") {
      fail("runtime endpoints are not the fixed same-origin endpoints");
    }
    if (config.simulation !== false || config.secret_free !== true) fail("runtime is not live and secret-free");
    if (config.rollback_status !== ROLLBACK_STATUS) fail("rollback status is not explicitly unimplemented");
    if (config.enrollment_capable !== false) fail("runtime unexpectedly permits enrollment");
    return config;
  }

  function validateObservationRuntime(config, browserOrigin) {
    exactKeys(config, [
      "schema_version", "state_schema_version", "expected_origin", "state_endpoint",
      "simulation", "read_only", "enrollment_capable", "refresh_interval_seconds"
    ], "observation runtime config");
    if (config.state_schema_version !== OBSERVATION_STATE_SCHEMA) fail("unsupported observation state schema");
    if (config.expected_origin !== browserOrigin) fail("browser origin does not match the station origin");
    if (config.state_endpoint !== "/api/v1/state") fail("state endpoint is not the fixed same-origin endpoint");
    if (config.simulation !== false || config.read_only !== true || config.enrollment_capable !== false) {
      fail("observation runtime is not live and read-only with enrollment disabled");
    }
    if (config.refresh_interval_seconds !== 5) fail("unsupported observation refresh interval");
    return config;
  }

  function timestamp(value, label) {
    text(value, label);
    if (!Number.isFinite(Date.parse(value))) fail(label + " must be a timestamp");
  }

  function stringArray(value, label) {
    if (!Array.isArray(value)) fail(label + " must be an array");
    value.forEach(function (entry) { text(entry, label + " entry"); });
  }

  function validateObservationState(value) {
    const state = object(value, "observation state");
    if (state.schema_version !== OBSERVATION_STATE_SCHEMA) fail("unsupported observation state schema");
    ["station_id", "lane_id", "transaction_id", "read_detail", "next_action"].forEach(function (field) {
      text(state[field], field);
    });
    if (!READ_STATUSES.has(state.read_status)) fail("unsupported read status");
    if (typeof state.stale !== "boolean") fail("stale must be a boolean");
    timestamp(state.last_attempted_read, "last attempted read");
    if (state.last_successful_read !== undefined) timestamp(state.last_successful_read, "last successful read");
    stringArray(state.unresolved_conditions, "unresolved conditions");
    const ports = object(state.local_ports, "local ports");
    timestamp(ports.observed_at, "local ports observation time");
    text(ports.detail, "local ports detail");
    ["usb", "uart"].forEach(function (name) {
      const port = object(ports[name], name + " port");
      text(port.path, name + " path");
      if (!["present", "absent", "unavailable"].includes(port.status)) fail("unsupported port status");
      ["vendor_id", "product_id"].forEach(function (field) {
        if (port[field] !== undefined) text(port[field], field);
      });
    });
    const snapshot = state.snapshot;
    if (state.read_status === "current" && !snapshot) fail("current response has no snapshot");
    if (!["current", "unavailable"].includes(state.read_status) && snapshot) fail("rejected read retained transaction details");
    if (state.stale !== (state.read_status === "unavailable" && !!snapshot)) fail("snapshot freshness is inconsistent");
    if (!snapshot) return state;
    if (!state.last_successful_read) fail("snapshot has no successful read time");
    object(snapshot, "snapshot");
    if (snapshot.id !== state.transaction_id) fail("snapshot transaction does not match selection");
    if (!Number.isSafeInteger(snapshot.resource_version) || snapshot.resource_version < 1) fail("invalid resource version");
    if (!OBSERVATION_STATUSES.has(snapshot.status)) fail("unsupported recorded transaction status");
    ["status_label", "asset_id", "intended_logical_id", "profile_id"].forEach(function (field) { text(snapshot[field], field); });
    timestamp(snapshot.updated_at, "authority update time");
    if (snapshot.evidence_basis !== "coordinator_recorded" || snapshot.fleet_admission !== "unevaluated") {
      fail("observation claims unsupported evidence or fleet admission");
    }
    const hardware = object(snapshot.hardware, "hardware facts");
    ["customer_key", "secure_boot", "jtag", "eeprom_write_protection"].forEach(function (field) {
      if (hardware[field] !== "unknown") fail("unsupported current hardware claim");
    });
    function stringFields(value, fields, label) {
      object(value, label);
      fields.forEach(function (field) { text(value[field], label + " " + field); });
    }
    function release(value) {
      stringFields(value, [
        "expected_eeprom_digest", "expected_boot_image_digest", "expected_customer_key_hash",
        "signed_release_manifest_digest", "lane_guard_package_digest", "compiled_artifact_set_digest"
      ], "expected release binding");
    }
    function claim(value) {
      stringFields(value, ["id", "station_id", "lane_id", "status"], "claim");
      if (!["active", "released", "transferred", "expired"].includes(value.status)) fail("invalid claim status");
      timestamp(value.acquired_at, "claim acquisition time");
      timestamp(value.expires_at, "claim expiry time");
    }
    if (snapshot.active_claim !== undefined) claim(snapshot.active_claim);
    if (!Array.isArray(snapshot.claim_history)) fail("claim history must be an array");
    snapshot.claim_history.forEach(claim);
    if (snapshot.recorded_prestate !== undefined) {
      stringFields(snapshot.recorded_prestate, ["fingerprint", "customer_key_hash", "observation_digest", "bound_at"], "recorded prestate");
      timestamp(snapshot.recorded_prestate.bound_at, "prestate recording time");
    }
    if (snapshot.approval !== undefined) {
      stringFields(snapshot.approval, [
        "id", "approver_id", "transaction_digest", "plan_digest", "station_id", "lane_id",
        "target_fingerprint", "audit_receipt_id", "approved_at", "expires_at"
      ], "approval");
      timestamp(snapshot.approval.approved_at, "approval recording time");
      timestamp(snapshot.approval.expires_at, "approval expiry time");
      stringArray(snapshot.approval.allowed_operations, "approved operations");
      release(snapshot.approval.release);
    }
    if (snapshot.quarantine !== undefined) {
      stringFields(snapshot.quarantine, ["reason_code", "audit_receipt_id", "observation_digest", "recorded_at"], "quarantine");
      timestamp(snapshot.quarantine.recorded_at, "quarantine recording time");
    }
    if (snapshot.security_applied !== undefined) {
      stringFields(snapshot.security_applied, ["audit_receipt_id", "evidence_digest", "recorded_at"], "development completion");
      timestamp(snapshot.security_applied.recorded_at, "development completion recording time");
    }
    if (snapshot.abort !== undefined) {
      stringFields(snapshot.abort, ["audit_receipt_id", "reusable_baseline_digest", "recorded_at"], "abort");
      timestamp(snapshot.abort.recorded_at, "abort recording time");
    }
    const expected = object(snapshot.expected, "expected bindings");
    ["customer_key_hash", "prestate_customer_key_hash", "bundle_digest", "policy_digest", "transaction_digest"].forEach(function (field) {
      text(expected[field], "expected " + field);
    });
    if (expected.release !== undefined) release(expected.release);
    if (!Array.isArray(snapshot.operations) || snapshot.operations.length !== OBSERVATION_OPERATIONS.length) {
      fail("observation must contain the seven operation rows");
    }
    snapshot.operations.forEach(function (entry, index) {
      const operation = object(entry, "operation");
      if (operation.sequence !== index + 1 || operation.operation !== OBSERVATION_OPERATIONS[index]) fail("operation order changed");
      if (!OPERATION_STATUSES.has(operation.status)) fail("unsupported operation status");
      text(operation.label, "operation label");
      text(operation.status_label, "operation status label");
      if (operation.status !== "not_recorded") text(operation.record_id, "operation record id");
      ["record_id", "intent_audit_receipt_id", "evidence_audit_receipt_id", "reconciliation_audit_receipt_id",
        "input_digest", "prestate_digest", "output_digest", "observation_digest"].forEach(function (field) {
        if (operation[field] !== undefined) text(operation[field], "operation " + field);
      });
      ["intent_at", "evidence_at"].forEach(function (field) {
        if (operation[field] !== undefined) timestamp(operation[field], "operation " + field);
      });
    });
    return state;
  }

  function validateActionPresentation(value, action) {
    const presentation = object(value, "action presentation");
    if (presentation.action !== action) fail("action presentation does not match allowed action");
    text(presentation.label, "action label");
    text(presentation.description, "action description");
    text(presentation.classification, "action classification");
    if (typeof presentation.requires_confirmation !== "boolean" || typeof presentation.point_of_no_return !== "boolean") {
      fail("action confirmation metadata is invalid");
    }
    if (presentation.classification === "irreversible" && (!presentation.requires_confirmation || !presentation.point_of_no_return)) {
      fail("irreversible action lacks explicit confirmation metadata");
    }
    return presentation;
  }

  function validateState(value, expectedSchema) {
    if (expectedSchema === OBSERVATION_STATE_SCHEMA) return validateObservationState(value);
    const state = object(value, "state");
    if (state.schema_version !== LIVE_STATE_SCHEMA) fail("unsupported state schema");
    if (!Number.isSafeInteger(state.revision) || state.revision < 1) fail("revision is not a positive safe integer");
    if (state.simulation !== false || state.secret_free !== true) fail("state is not live and secret-free");
    text(state.phase, "phase");
    text(state.instruction, "instruction");
    if (state.phase === "enrollment_ready" || state.lifecycle === "enrollment_ready") fail("enrollment-ready lifecycle is prohibited");
    const safety = object(state.safety, "safety");
    if (safety.simulation !== false || safety.secret_free !== true) fail("safety boundary is not live and secret-free");
    if (safety.rollback_status !== ROLLBACK_STATUS) fail("rollback gate is not explicitly unimplemented");
    if (safety.enrollment_capable !== false) fail("state unexpectedly permits enrollment");
    if (!Array.isArray(state.allowed_actions) || !Array.isArray(state.action_presentations)) {
      fail("allowed actions and presentations must be arrays");
    }
    const seen = new Set();
    const presentations = new Map();
    state.action_presentations.forEach(function (entry) {
      const candidate = object(entry, "action presentation");
      const action = text(candidate.action, "presented action");
      if (presentations.has(action)) fail("duplicate action presentation");
      presentations.set(action, candidate);
    });
    state.allowed_actions.forEach(function (action) {
      if (typeof action !== "string" || !SUPPORTED_ACTIONS.has(action) || action === FORBIDDEN_ACTION) {
        fail("unsupported or enrollment action was offered");
      }
      if (seen.has(action)) fail("duplicate allowed action");
      seen.add(action);
      if (!presentations.has(action)) fail("allowed action has no presentation");
      validateActionPresentation(presentations.get(action), action);
    });
    if (presentations.size !== seen.size) fail("presentation exists for an action that is not allowed");
    if (!Array.isArray(state.evidence)) fail("evidence must be an array");
    state.evidence.forEach(function (entry) {
      const evidence = object(entry, "evidence entry");
      ["id", "stage", "status", "digest", "detail", "receipt_id", "recorded_at"].forEach(function (field) {
        text(evidence[field], "evidence " + field);
      });
    });
    return state;
  }

  function buildActionRequest(action, revision) {
    if (!SUPPORTED_ACTIONS.has(action) || action === FORBIDDEN_ACTION) fail("cannot construct unsupported action");
    if (!Number.isSafeInteger(revision) || revision < 1) fail("cannot construct action with invalid revision");
    return { action: action, expected_revision: revision };
  }

  function requiresExplicitConfirmation(presentation) {
    return presentation.classification === "irreversible" || presentation.point_of_no_return === true || presentation.requires_confirmation === true;
  }

  function addFact(document, list, label, value) {
    const term = document.createElement("dt");
    term.textContent = label;
    const detail = document.createElement("dd");
    detail.textContent = value || "Not recorded";
    list.append(term, detail);
  }

  function renderFacts(document, list, value, definitions, emptyMessage) {
    list.replaceChildren();
    if (!value) {
      addFact(document, list, "Status", emptyMessage);
      return;
    }
    definitions.forEach(function (definition) {
      const fact = value[definition[1]];
      addFact(document, list, definition[0], fact === undefined || fact === null || fact === "" ? "Not recorded" : String(fact));
    });
  }

  function renderEvidence(document, evidence) {
    const list = document.getElementById("evidence-list");
    list.replaceChildren();
    evidence.forEach(function (entry) {
      const item = document.createElement("li");
      const heading = document.createElement("div");
      const id = document.createElement("strong");
      id.textContent = entry.id || "unnamed evidence";
      const status = document.createElement("span");
      status.className = "evidence-status status-" + String(entry.status || "unknown").replace(/[^a-z0-9_-]/g, "-");
      status.textContent = entry.status || "unknown";
      heading.append(id, status);
      const detail = document.createElement("p");
      detail.textContent = entry.detail || "No detail supplied.";
      const binding = document.createElement("code");
      binding.textContent = (entry.stage || "unknown stage") + " · " + (entry.receipt_id || "missing receipt");
      item.append(heading, detail, binding);
      list.append(item);
    });
    document.getElementById("evidence-count").textContent = evidence.length + (evidence.length === 1 ? " record" : " records");
  }

  function confirmationMessage(presentation) {
    if (presentation.classification === "irreversible" || presentation.point_of_no_return) {
      return "IRREVERSIBLE ONE-SHOT ACTION\n\n" + presentation.description +
        "\n\nConfirm only after checking the target, current fence epoch, approval, plan, and durable intent receipt. This action must never be blindly repeated.";
    }
    return "Confirm action\n\n" + presentation.description;
  }

  function renderActions(windowObject, runtime, state, reload) {
    const document = windowObject.document;
    const container = document.getElementById("actions");
    container.replaceChildren();
    const presentations = new Map(state.action_presentations.map(function (entry) { return [entry.action, entry]; }));
    if (state.allowed_actions.length === 0) {
      const empty = document.createElement("p");
      empty.className = "empty";
      empty.textContent = "No action is authorized in the current phase.";
      container.append(empty);
      return;
    }
    state.allowed_actions.forEach(function (action) {
      const presentation = presentations.get(action);
      const card = document.createElement("article");
      card.className = "action-card" + (presentation.point_of_no_return ? " irreversible" : "");
      const title = document.createElement("h3");
      title.textContent = presentation.label;
      const description = document.createElement("p");
      description.textContent = presentation.description;
      const classification = document.createElement("span");
      classification.className = "classification";
      classification.textContent = presentation.classification.replace(/_/g, " ");
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = presentation.point_of_no_return ? "Review and execute once" : "Run action";
      button.addEventListener("click", async function () {
        if (requiresExplicitConfirmation(presentation) && !windowObject.confirm(confirmationMessage(presentation))) return;
        button.disabled = true;
        setConnection(document, "Submitting action for revision " + state.revision + "…", "working");
        try {
          const response = await windowObject.fetch(runtime.action_endpoint, {
            method: "POST",
            credentials: "same-origin",
            redirect: "error",
            referrerPolicy: "no-referrer",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(buildActionRequest(action, state.revision))
          });
          if (!response.ok) {
            const problem = await response.json().catch(function () { return {}; });
            throw new Error(problem.detail || ("Action failed with HTTP " + response.status));
          }
          render(windowObject, runtime, validateState(await response.json()), reload);
          setConnection(document, "Authoritative state updated.", "ok");
        } catch (error) {
          setConnection(document, error.message, "error");
          await reload();
        } finally {
          button.disabled = false;
        }
      });
      card.append(title, description, classification, button);
      container.append(card);
    });
  }

  function setConnection(document, message, status) {
    const element = document.getElementById("connection-status");
    element.textContent = message;
    element.dataset.status = status;
  }

  function render(windowObject, runtime, state, reload) {
    if (runtime.schema_version === OBSERVATION_RUNTIME_SCHEMA) return renderObservation(windowObject.document, state);
    const document = windowObject.document;
    document.getElementById("phase-title").textContent = state.phase.replace(/_/g, " ");
    document.getElementById("instruction").textContent = state.instruction;
    document.getElementById("revision").textContent = "Revision " + state.revision;
    renderFacts(document, document.getElementById("target-facts"), state.target, [
      ["Model", "model"], ["Profile", "profile_id"], ["Fingerprint", "target_fingerprint"],
      ["Customer key", "customer_key_hash"], ["Secure boot", "secure_boot_state"]
    ], "No target is bound");
    renderFacts(document, document.getElementById("transaction-facts"), state.transaction, [
      ["Transaction", "id"], ["Status", "status"], ["Claim", "claim_id"],
      ["Fence epoch", "fence_epoch"], ["Plan", "plan_digest"], ["Commit executions", "commit_executions"]
    ], "No transaction exists");
    renderEvidence(document, state.evidence);
    renderActions(windowObject, runtime, state, reload);
  }

  function configureObservationView(document) {
    document.getElementById("station-label").textContent = "Read-only station";
    document.getElementById("station-title").textContent = "Kaiba Transaction Status";
    document.getElementById("mode-marker").textContent = "Read-only viewer";
    document.getElementById("safety-label").textContent = "Recorded coordinator state";
    document.getElementById("safety-title").textContent = "Fleet admission has not been evaluated";
    document.getElementById("safety-description").textContent = "This viewer reports recorded results and references. It cannot perform hardware operations or enrollment, and does not independently verify audit receipts or current hardware protections.";
    document.getElementById("phase-label").textContent = "Recorded transaction status";
    document.getElementById("target-label").textContent = "Coordinator binding and current unknowns";
    document.getElementById("target-title").textContent = "Bound device";
    document.getElementById("evidence-label").textContent = "Coordinator-recorded references";
    document.getElementById("evidence-title").textContent = "Recorded results and references";
    document.getElementById("action-panel").hidden = true;
    document.getElementById("actions").replaceChildren();
    ["observation-times", "operation-panel", "condition-panel", "port-panel", "observation-diagnostics"].forEach(function (id) {
      document.getElementById(id).hidden = false;
    });
  }

  function displayTime(value) {
    return value ? new Date(value).toISOString() : "Not yet checked";
  }

  function appendFacts(document, list, value, definitions) {
    if (!value) return;
    definitions.forEach(function (definition) {
      const fact = value[definition[1]];
      if (fact !== undefined && fact !== null && fact !== "") addFact(document, list, definition[0], String(fact));
    });
  }

  function renderRecordedReferences(document, snapshot) {
    const list = document.getElementById("evidence-list");
    list.replaceChildren();
    let count = 0;
    function record(title, description, value, fields) {
      count += 1;
      const item = document.createElement("li");
      const heading = document.createElement("strong");
      heading.textContent = title;
      const detail = document.createElement("p");
      detail.textContent = description;
      const diagnostics = document.createElement("details");
      diagnostics.className = "record-details";
      const summary = document.createElement("summary");
      summary.textContent = "Recorded identifiers and digests";
      const facts = document.createElement("dl");
      facts.className = "facts";
      appendFacts(document, facts, value, fields);
      diagnostics.append(summary, facts);
      item.append(heading, detail, diagnostics);
      list.append(item);
    }
    if (snapshot) {
      if (snapshot.approval) record("Commit approval", "The coordinator recorded an approval. This viewer does not grant execution authority.", snapshot.approval, [
        ["Approval", "id"], ["Approver", "approver_id"], ["Receipt", "audit_receipt_id"],
        ["Approved", "approved_at"], ["Expires", "expires_at"], ["Plan digest", "plan_digest"],
        ["Transaction digest", "transaction_digest"], ["Station", "station_id"], ["Lane", "lane_id"],
        ["Fence epoch", "fence_epoch"], ["Target fingerprint", "target_fingerprint"], ["Approved operations", "allowed_operations"]
      ]);
      snapshot.operations.filter(function (operation) { return operation.status !== "not_recorded"; }).forEach(function (operation) {
        record(operation.label, operation.status_label + ". These references have not been independently verified by this viewer.", operation, [
          ["Record", "record_id"], ["Intent recorded", "intent_at"], ["Result recorded", "evidence_at"],
          ["Intent receipt", "intent_audit_receipt_id"], ["Result receipt", "evidence_audit_receipt_id"],
          ["Reconciliation receipt", "reconciliation_audit_receipt_id"], ["Input digest", "input_digest"],
          ["Prestate digest", "prestate_digest"], ["Output digest", "output_digest"], ["Observation digest", "observation_digest"]
        ]);
      });
      if (snapshot.quarantine) record("Quarantine", "The coordinator recorded a quarantine condition.", snapshot.quarantine, [
        ["Reason", "reason_code"], ["Receipt", "audit_receipt_id"], ["Observation digest", "observation_digest"], ["Recorded", "recorded_at"]
      ]);
      if (snapshot.security_applied) record("Development completion", "Security applied is development completion. Fleet admission remains unevaluated.", snapshot.security_applied, [
        ["Receipt", "audit_receipt_id"], ["Evidence digest", "evidence_digest"], ["Recorded", "recorded_at"]
      ]);
      if (snapshot.abort) record("Aborted transaction", "The coordinator recorded an aborted transaction.", snapshot.abort, [
        ["Receipt", "audit_receipt_id"], ["Reusable baseline digest", "reusable_baseline_digest"], ["Recorded", "recorded_at"]
      ]);
    }
    document.getElementById("evidence-count").textContent = count + (count === 1 ? " record" : " records");
    if (count === 0) {
      const empty = document.createElement("li");
      empty.textContent = snapshot ? "No approval, operation results, or terminal records have been recorded." : "No transaction references are available.";
      list.append(empty);
    }
  }

  function renderObservation(document, state) {
    configureObservationView(document);
    const snapshot = state && state.snapshot;
    document.getElementById("phase-title").textContent = snapshot ? snapshot.status_label : "Transaction status unknown";
    document.getElementById("instruction").textContent = state ? state.next_action : "Waiting for a valid station response. No transaction details are available.";
    document.getElementById("revision").textContent = snapshot ? "Resource version " + snapshot.resource_version : "Resource version —";
    const times = document.getElementById("observation-time-facts");
    times.replaceChildren();
    addFact(document, times, "Authority updated", snapshot ? displayTime(snapshot.updated_at) : "Unknown");
    addFact(document, times, "Last successfully checked", displayTime(state && state.last_successful_read));
    addFact(document, times, "Last attempted authority read", displayTime(state && state.last_attempted_read));
    const target = document.getElementById("target-facts");
    target.replaceChildren();
    addFact(document, target, "Asset", snapshot ? snapshot.asset_id : "Unknown");
    addFact(document, target, "Profile", snapshot ? snapshot.profile_id : "Unknown");
    addFact(document, target, "Target binding", snapshot ? (snapshot.recorded_prestate ? "Recorded prestate; current device not authenticated" : "Not recorded") : "Unknown");
    addFact(document, target, "Current customer key", "Unknown");
    addFact(document, target, "Current secure boot", "Unknown");
    addFact(document, target, "Current JTAG protection", "Unknown");
    addFact(document, target, "Current EEPROM write protection", "Unknown");
    const transaction = document.getElementById("transaction-facts");
    transaction.replaceChildren();
    addFact(document, transaction, "Status", snapshot ? snapshot.status_label : "Unknown");
    addFact(document, transaction, "Recorded claim status", snapshot && snapshot.active_claim ? snapshot.active_claim.status.replace(/_/g, " ") : "Not recorded");
    addFact(document, transaction, "Fleet admission", "Unevaluated");
    addFact(document, transaction, "Evidence source", snapshot ? "Coordinator records; references not independently verified" : "Unavailable");
    const operations = document.getElementById("operation-list");
    operations.replaceChildren();
    if (snapshot) snapshot.operations.forEach(function (operation) {
      const item = document.createElement("li");
      const row = document.createElement("div");
      const label = document.createElement("strong");
      label.textContent = operation.sequence + ". " + operation.label;
      const status = document.createElement("span");
      status.className = "evidence-status status-" + operation.status;
      status.textContent = operation.status_label;
      row.append(label, status);
      item.append(row);
      operations.append(item);
    });
    if (!snapshot) {
      const empty = document.createElement("li");
      empty.textContent = "Operation records are unavailable.";
      operations.append(empty);
    }
    const conditions = document.getElementById("condition-list");
    conditions.replaceChildren();
    (state ? state.unresolved_conditions : ["No valid authority snapshot is available."]).forEach(function (condition) {
      const item = document.createElement("li");
      item.textContent = condition;
      conditions.append(item);
    });
    const ports = document.getElementById("port-facts");
    ports.replaceChildren();
    if (state) {
      addFact(document, ports, "Ports observed", displayTime(state.local_ports.observed_at));
      addFact(document, ports, "USB sysfs entry", state.local_ports.usb.status);
      addFact(document, ports, "USB vendor / product", [state.local_ports.usb.vendor_id || "Unknown", state.local_ports.usb.product_id || "Unknown"].join(" / "));
      addFact(document, ports, "UART node", state.local_ports.uart.status);
      addFact(document, ports, "Observation limits", state.local_ports.detail);
    } else addFact(document, ports, "Status", "Unknown");
    const diagnostics = document.getElementById("diagnostic-facts");
    diagnostics.replaceChildren();
    if (state) {
      appendFacts(document, diagnostics, state, [["Configured transaction", "transaction_id"], ["Station", "station_id"], ["Lane", "lane_id"]]);
      addFact(document, diagnostics, "USB sysfs path", state.local_ports.usb.path);
      addFact(document, diagnostics, "UART path", state.local_ports.uart.path);
    }
    if (snapshot) {
      addFact(document, diagnostics, "Intended logical ID", snapshot.intended_logical_id);
      appendFacts(document, diagnostics, snapshot.recorded_prestate, [
        ["Recorded target fingerprint", "fingerprint"], ["Recorded prestate customer key", "customer_key_hash"],
        ["Recorded prestate observation digest", "observation_digest"], ["Prestate recorded", "bound_at"]
      ]);
      appendFacts(document, diagnostics, snapshot.expected, [
        ["Expected customer key", "customer_key_hash"], ["Expected prestate customer key", "prestate_customer_key_hash"],
        ["Expected bundle digest", "bundle_digest"], ["Expected policy digest", "policy_digest"], ["Transaction binding digest", "transaction_digest"]
      ]);
      appendFacts(document, diagnostics, snapshot.expected.release, [
        ["Expected EEPROM digest", "expected_eeprom_digest"], ["Expected boot image digest", "expected_boot_image_digest"],
        ["Expected release customer key", "expected_customer_key_hash"], ["Signed release manifest digest", "signed_release_manifest_digest"],
        ["Lane guard package digest", "lane_guard_package_digest"], ["Compiled artifact set digest", "compiled_artifact_set_digest"]
      ]);
      appendFacts(document, diagnostics, snapshot.active_claim, [
        ["Recorded active claim ID", "id"], ["Claim acquired", "acquired_at"], ["Claim lease expires", "expires_at"],
        ["Claim station", "station_id"], ["Claim lane", "lane_id"]
      ]);
      (snapshot.claim_history || []).forEach(function (claim) {
        addFact(document, diagnostics, "Historical claim", claim.id + " · " + claim.station_id + " / " + claim.lane_id + " · " + claim.status);
      });
    }
    renderRecordedReferences(document, snapshot);
    const message = !state ? "Waiting for station state." : (state.stale ? "STALE — " : "") + state.read_detail;
    setConnection(document, message, !state ? "working" : state.read_status === "current" ? "ok" : state.stale ? "stale" : "error");
  }

  async function readJSON(response, label) {
    if (!response.ok) {
      const error = new Error(label + " failed with HTTP " + response.status);
      error.clearObservation = response.status < 500 || response.status > 599;
      throw error;
    }
    const contentType = response.headers.get("Content-Type") || "";
    if (contentType.split(";", 1)[0].trim().toLowerCase() !== "application/json") fail(label + " returned a non-JSON response");
    try {
      return await response.json();
    } catch (_) {
      fail(label + " returned malformed JSON");
    }
  }

  async function start(windowObject) {
    const runtimeResponse = await windowObject.fetch("/runtime-config.json", {
      method: "GET", credentials: "same-origin", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer"
    });
    const runtime = validateRuntimeConfig(await readJSON(runtimeResponse, "Runtime config"), windowObject.location.origin);
    if (runtime.schema_version === guided.RUNTIME) return guided.start(windowObject, runtime);
    const observer = runtime.schema_version === OBSERVATION_RUNTIME_SCHEMA;
    let lastState = null;
    let pending = null;
    let timer = null;
    let stopped = false;
    const refresh = windowObject.document.getElementById("refresh");
    if (observer) renderObservation(windowObject.document, null);
    const reload = function () {
      if (pending) return pending;
      if (stopped) return Promise.resolve();
      if (timer !== null) windowObject.clearTimeout(timer);
      refresh.disabled = true;
      pending = Promise.resolve().then(async function () {
        try {
          const response = await windowObject.fetch(runtime.state_endpoint, {
            method: "GET", credentials: "same-origin", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer"
          });
          const state = validateState(await readJSON(response, "Live state"), runtime.state_schema_version);
          lastState = state;
          render(windowObject, runtime, state, reload);
          if (!observer) setConnection(windowObject.document, "Connected to the local authoritative orchestrator.", "ok");
        } catch (error) {
          if (observer) {
            if (error.clearObservation) lastState = null;
            renderObservation(windowObject.document, lastState);
            const retained = lastState && lastState.snapshot;
            windowObject.document.getElementById("instruction").textContent = "Restore the station connection and refresh before relying on recorded progress.";
            setConnection(windowObject.document, (retained ? "STALE — " : "Status unavailable — ") + error.message + ". Local port observations may also be out of date.", retained ? "stale" : "error");
          } else setConnection(windowObject.document, error.message, "error");
        } finally {
          pending = null;
          refresh.disabled = false;
          if (observer && !stopped) timer = windowObject.setTimeout(reload, runtime.refresh_interval_seconds * 1000);
        }
      });
      return pending;
    };
    refresh.addEventListener("click", reload);
    const stop = function () {
      stopped = true;
      if (timer !== null) windowObject.clearTimeout(timer);
    };
    windowObject.addEventListener("pagehide", stop);
    windowObject.addEventListener("pageshow", function (event) {
      if (!event.persisted) return;
      stopped = false;
      if (observer) {
        const retained = lastState && lastState.snapshot;
        setConnection(windowObject.document, retained ? "STALE — Checking authority state after returning to this page." : "Checking station state after returning to this page.", retained ? "stale" : "working");
      }
      reload();
    });
    await reload();
    return { reload: reload, stop: stop };
  }

  function showFatal(document, error) {
    const element = document.getElementById("connection-status");
    if (element) {
      element.textContent = error.message;
      element.dataset.status = "error";
    }
  }

  return {
    RUNTIME_SCHEMA: RUNTIME_SCHEMA,
    LIVE_STATE_SCHEMA: LIVE_STATE_SCHEMA,
    OBSERVATION_RUNTIME_SCHEMA: OBSERVATION_RUNTIME_SCHEMA,
    OBSERVATION_STATE_SCHEMA: OBSERVATION_STATE_SCHEMA,
    validateRuntimeConfig: validateRuntimeConfig,
    validateState: validateState,
    validateObservationState: validateObservationState,
    buildActionRequest: buildActionRequest,
    requiresExplicitConfirmation: requiresExplicitConfirmation,
    start: start,
    showFatal: showFatal
  };
});
