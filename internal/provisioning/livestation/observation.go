package livestation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/authorityhttp"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaign"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
)

// Observer owns only an in-memory last successful projection. Restart recovery
// comes from the configured transaction ID and a fresh authority read.
type Observer struct {
	config         ObservationConfig
	reader         TransactionReader
	gate           chan struct{}
	clock          func() time.Time
	lastSuccessful *time.Time
	snapshot       *TransactionObservation
}

func NewObserver(config ObservationConfig, reader TransactionReader) (*Observer, error) {
	if !liveIDPattern.MatchString(config.StationID) || !liveIDPattern.MatchString(config.LaneID) || !liveIDPattern.MatchString(config.TransactionID) {
		return nil, errors.New("fixed station, lane, and transaction identifiers are required")
	}
	if !filepath.IsAbs(config.USBPath) || !filepath.IsAbs(config.UARTPath) {
		return nil, errors.New("absolute USB sysfs and UART paths are required")
	}
	if reader == nil {
		return nil, errors.New("transaction reader is required")
	}
	return &Observer{config: config, reader: reader, gate: make(chan struct{}, 1), clock: time.Now}, nil
}

func (observer *Observer) Current(ctx context.Context) (ObservationState, error) {
	// The lock covers the read and projection, so a slow old result can never
	// replace a later denial. Waiters can leave when their browser disconnects.
	select {
	case observer.gate <- struct{}{}:
		defer func() { <-observer.gate }()
	case <-ctx.Done():
		return ObservationState{}, ctx.Err()
	}
	state := ObservationState{
		SchemaVersion: ObservationStateSchemaVersion,
		StationID:     observer.config.StationID, LaneID: observer.config.LaneID,
		TransactionID: observer.config.TransactionID, LastAttemptedRead: observer.clock().UTC(),
	}
	transaction, err := observer.reader.GetTransaction(ctx, observer.config.TransactionID)
	if err == nil {
		var projected *TransactionObservation
		projected, err = projectTransaction(transaction, observer.config)
		if err == nil {
			observer.snapshot = projected
			checkedAt := observer.clock().UTC()
			observer.lastSuccessful = &checkedAt
		} else {
			err = &authorityhttp.InvalidResponseError{Err: err}
		}
	}
	state.ReadStatus, state.ReadDetail = observationReadResult(err)
	if state.ReadStatus != "current" && state.ReadStatus != "unavailable" {
		observer.snapshot = nil
		observer.lastSuccessful = nil
	}
	state.Snapshot = cloneObservation(observer.snapshot)
	if observer.lastSuccessful != nil {
		checkedAt := *observer.lastSuccessful
		state.LastSuccessfulRead = &checkedAt
	}
	state.Stale = state.ReadStatus == "unavailable" && state.Snapshot != nil
	state.LocalPorts = observePorts(observer.config, observer.clock().UTC())
	state.UnresolvedConditions, state.NextAction = observationGuidance(state)
	return state, nil
}

func observationReadResult(err error) (string, string) {
	if err == nil {
		return "current", "Transaction successfully read from the control authority."
	}
	var invalid *authorityhttp.InvalidResponseError
	var status *authorityhttp.HTTPStatusError
	switch {
	case errors.As(err, &invalid):
		return "invalid_response", "The authority response could not be validated; transaction details have been cleared."
	case errors.As(err, &status):
		switch {
		case status.StatusCode == http.StatusUnauthorized || status.StatusCode == http.StatusForbidden:
			return "denied", "The control authority denied access; transaction details have been cleared."
		case status.StatusCode == http.StatusNotFound:
			return "not_found", "The configured transaction was not found; transaction details have been cleared."
		case status.StatusCode >= 500 && status.StatusCode <= 599:
			return "unavailable", "The control authority is unavailable. Any retained transaction is the last successful observation."
		default:
			return "invalid_response", "The authority returned an unexpected response; transaction details have been cleared."
		}
	default:
		return "unavailable", "The control authority could not be reached. Any retained transaction is the last successful observation."
	}
}

var transactionStatusLabels = map[controlplane.TransactionStatus]string{
	controlplane.StatusCreated:                "Created",
	controlplane.StatusClaimed:                "Claimed",
	controlplane.StatusTargetBound:            "Target bound",
	controlplane.StatusCommitApproved:         "Commit approved",
	controlplane.StatusMutationInProgress:     "Mutation in progress",
	controlplane.StatusReconciliationRequired: "Reconciliation required",
	controlplane.StatusReconciled:             "Reconciled",
	controlplane.StatusSecurityApplied:        "Development security applied",
	controlplane.StatusAborted:                "Aborted",
	controlplane.StatusQuarantined:            "Quarantined",
}

var operationStatusLabels = map[controlplane.OperationStatus]string{
	controlplane.OperationIntentRecorded:      "Intent recorded",
	controlplane.OperationSucceeded:           "Succeeded",
	controlplane.OperationFailed:              "Failed",
	controlplane.OperationUncertain:           "Uncertain",
	controlplane.OperationConfirmedApplied:    "Confirmed applied",
	controlplane.OperationConfirmedNotApplied: "Confirmed not applied",
}

var observationOperationLabels = map[campaign.Operation]string{
	campaign.OperationProgramCustomerKeyAndEEPROM: "Program customer key and EEPROM",
	campaign.OperationColdPowerCycle:              "Cold power cycle",
	campaign.OperationOwnedReadback:               "Owned-device readback",
	campaign.OperationTestOwnedRecovery:           "Owned recovery test",
	campaign.OperationPostRecoveryReadback:        "Post-recovery readback",
	campaign.OperationTestNegativeBoot:            "Negative boot test",
	campaign.OperationTestRootIntegrity:           "Root integrity test",
}

func projectTransaction(transaction controlplane.Transaction, config ObservationConfig) (*TransactionObservation, error) {
	if transaction.ID != config.TransactionID {
		return nil, errors.New("transaction does not match configured selection")
	}
	if err := controlplane.ValidateTransactionSnapshot(transaction); err != nil {
		return nil, err
	}
	// This is an additional response consistency check, not read authorization.
	// The control server determines the active or latest historical read owner.
	owner := transaction.ActiveClaim
	if owner == nil {
		for index := range transaction.ClaimHistory {
			claim := &transaction.ClaimHistory[index]
			if owner == nil || claim.FenceEpoch > owner.FenceEpoch {
				owner = claim
			}
		}
	}
	if owner == nil || owner.StationID != config.StationID || owner.LaneID != config.LaneID {
		return nil, errors.New("transaction read owner does not match station and lane")
	}
	operations := campaign.DevelopmentOperations()
	if len(transaction.Operations) > len(operations) {
		return nil, errors.New("transaction contains excess operations")
	}
	snapshot := &TransactionObservation{
		ID: transaction.ID, ResourceVersion: transaction.ResourceVersion, Status: transaction.Status,
		StatusLabel: transactionStatusLabels[transaction.Status], UpdatedAt: transaction.UpdatedAt,
		AssetID: transaction.AssetID, IntendedLogicalID: transaction.IntendedLogicalID, ProfileID: transaction.ProfileID,
		ClaimHistory: []ClaimObservation{}, RecordedPrestate: transaction.Target,
		Expected: ExpectedBindings{CustomerKeyHash: transaction.ExpectedCustomerKeyHash,
			PrestateCustomerKeyHash: transaction.ExpectedPrestateCustomerKeyHash,
			BundleDigest:            transaction.BundleDigest, PolicyDigest: transaction.PolicyDigest, TransactionDigest: transaction.TransactionDigest},
		Approval: transaction.Approval, Operations: make([]OperationObservation, len(operations)), Quarantine: transaction.Quarantine,
		SecurityApplied: transaction.SecurityApplied, Abort: transaction.Abort,
		Hardware:      HardwareUnknowns{CustomerKey: "unknown", SecureBoot: "unknown", JTAG: "unknown", EEPROMWriteProtection: "unknown"},
		EvidenceBasis: "coordinator_recorded", FleetAdmission: "unevaluated",
	}
	if transaction.ActiveClaim != nil {
		claim := projectClaim(*transaction.ActiveClaim)
		snapshot.ActiveClaim = &claim
	}
	for _, claim := range transaction.ClaimHistory {
		snapshot.ClaimHistory = append(snapshot.ClaimHistory, projectClaim(claim))
	}
	if transaction.Approval != nil {
		release := transaction.Approval.Release
		snapshot.Expected.Release = &release
	} else if len(transaction.Operations) != 0 {
		release := transaction.Operations[0].Release
		snapshot.Expected.Release = &release
	}
	for index, operation := range operations {
		row := OperationObservation{Sequence: index + 1, Operation: string(operation), Label: observationOperationLabels[operation], Status: "not_recorded", StatusLabel: "Not recorded"}
		if index < len(transaction.Operations) {
			record := transaction.Operations[index]
			if record.Operation != string(operation) {
				return nil, fmt.Errorf("operation %d does not match the canonical campaign", index+1)
			}
			row.Status, row.StatusLabel = string(record.Status), operationStatusLabels[record.Status]
			row.RecordID, row.IntentAt, row.EvidenceAt = record.ID, &record.IntentAt, record.EvidenceAt
			row.IntentAuditReceiptID, row.EvidenceAuditReceiptID = record.IntentAuditReceiptID, record.EvidenceAuditReceiptID
			row.ReconciliationAuditReceiptID = record.ReconciliationAuditReceiptID
			row.InputDigest, row.PrestateDigest = record.InputDigest, record.PrestateDigest
			row.OutputDigest, row.ObservationDigest = record.OutputDigest, record.ObservationDigest
		}
		snapshot.Operations[index] = row
	}
	return cloneObservation(snapshot), nil
}

func projectClaim(claim controlplane.Claim) ClaimObservation {
	return ClaimObservation{ID: claim.ID, StationID: claim.StationID, LaneID: claim.LaneID,
		Mode: claim.Mode, Status: claim.Status, FenceEpoch: claim.FenceEpoch,
		AcquiredAt: claim.AcquiredAt, ExpiresAt: claim.ExpiresAt, ClosedAt: claim.ClosedAt}
}

func cloneObservation(snapshot *TransactionObservation) *TransactionObservation {
	if snapshot == nil {
		return nil
	}
	// This typed, validated projection contains only JSON-compatible values.
	// Copy every nested reference so callers cannot mutate the retained snapshot.
	data, _ := json.Marshal(snapshot)
	var clone TransactionObservation
	_ = json.Unmarshal(data, &clone)
	return &clone
}

func observationGuidance(state ObservationState) ([]string, string) {
	conditions := []string{
		"Current hardware security state has not been independently observed.",
		"Evidence and receipt references are coordinator-recorded; independent audit verification has not been performed.",
		"Fleet admission has not been evaluated.",
	}
	switch state.ReadStatus {
	case "unavailable":
		return append([]string{"The authority is unavailable; retained progress may be out of date."}, conditions...), "Restore the authority connection and refresh before relying on transaction progress."
	case "denied":
		return append([]string{"The station and lane are not authorized to read this transaction."}, conditions...), "Have the authority administrator verify the configured transaction and station/lane access."
	case "not_found":
		return append([]string{"The configured transaction does not exist at this authority."}, conditions...), "Verify the configured transaction ID and control authority."
	case "invalid_response":
		return append([]string{"The authority response failed validation."}, conditions...), "Have the authority administrator investigate the invalid response before relying on progress."
	}
	if state.Snapshot == nil {
		return conditions, "Refresh to read the configured transaction."
	}
	snapshot := state.Snapshot
	if snapshot.Status == controlplane.StatusQuarantined {
		return append([]string{"The transaction is quarantined; no further lane operations are permitted."}, conditions...), "Keep the target quarantined and have an authorized operator review the recorded reason and evidence."
	}
	if snapshot.Status == controlplane.StatusAborted {
		return append([]string{"The transaction has been aborted."}, conditions...), "Review the abort record with an authorized operator; this viewer cannot restart the transaction."
	}
	for _, operation := range snapshot.Operations {
		if operation.Status == string(controlplane.OperationIntentRecorded) || operation.Status == string(controlplane.OperationUncertain) || operation.Status == string(controlplane.OperationFailed) {
			return append([]string{"An operation has a pending, uncertain, or failed outcome that requires reconciliation."}, conditions...), "Have an authorized operator reconcile direct target state through the existing workflow; do not repeat the operation."
		}
		if operation.Status == string(controlplane.OperationConfirmedNotApplied) {
			return append([]string{"An operation was confirmed not applied; this campaign cannot be resumed."}, conditions...), "Have an authorized operator review the reconciliation and choose the permitted recovery path; do not retry this campaign."
		}
	}
	if snapshot.Status == controlplane.StatusReconciliationRequired {
		return append([]string{"The transaction requires reconciliation."}, conditions...), "Have an authorized operator reconcile direct target state through the existing workflow; do not repeat an operation."
	}
	if snapshot.Status == controlplane.StatusSecurityApplied {
		return conditions, "Review the development completion record and outstanding fleet admission requirements with an authorized operator."
	}
	if snapshot.RecordedPrestate == nil {
		conditions = append([]string{"No target binding has been recorded."}, conditions...)
	}
	return conditions, "Review the recorded progress with an authorized operator using the existing workflow. This viewer cannot run operations or qualify a board."
}

func observePorts(config ObservationConfig, now time.Time) LocalPortObservations {
	usb := observePort(config.USBPath)
	if usb.Status == "present" {
		usb.VendorID = readUSBIdentifier(filepath.Join(config.USBPath, "idVendor"))
		usb.ProductID = readUSBIdentifier(filepath.Join(config.USBPath, "idProduct"))
	}
	return LocalPortObservations{ObservedAt: now, USB: usb, UART: observePort(config.UARTPath),
		Detail: "Port visibility does not authenticate the bound device. RPIBOOT absence during normal boot is not a qualification failure. UART presence does not establish a connection."}
}

func observePort(path string) PortObservation {
	observation := PortObservation{Path: path, Status: "present"}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		observation.Status = "absent"
	} else if err != nil {
		observation.Status = "unavailable"
	}
	return observation
}

var usbIdentifierPattern = regexp.MustCompile(`^[0-9a-fA-F]{4}$`)

func readUSBIdentifier(path string) string {
	// These are tiny sysfs attributes, never a UART or a hardware command.
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 16))
	value := strings.TrimSpace(string(data))
	if err != nil || !usbIdentifierPattern.MatchString(value) {
		return ""
	}
	return strings.ToLower(value)
}
