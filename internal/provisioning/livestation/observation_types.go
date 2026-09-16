package livestation

import (
	"context"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/controlplane"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releasebinding"
)

const (
	ObservationRuntimeSchemaVersion = "provisioning.kaiba.network/station-observation-runtime/v1alpha1"
	ObservationStateSchemaVersion   = "provisioning.kaiba.network/station-observation-state/v1alpha1"
)

// TransactionReader intentionally grants no command, claim, or audit capability.
type TransactionReader interface {
	GetTransaction(context.Context, string) (controlplane.Transaction, error)
}

type ObservationSource interface {
	Current(context.Context) (ObservationState, error)
}

type ObservationConfig struct {
	StationID     string
	LaneID        string
	TransactionID string
	USBPath       string
	UARTPath      string
}

type ObservationRuntime struct {
	SchemaVersion          string `json:"schema_version"`
	StateSchemaVersion     string `json:"state_schema_version"`
	ExpectedOrigin         string `json:"expected_origin"`
	StateEndpoint          string `json:"state_endpoint"`
	Simulation             bool   `json:"simulation"`
	ReadOnly               bool   `json:"read_only"`
	EnrollmentCapable      bool   `json:"enrollment_capable"`
	RefreshIntervalSeconds int    `json:"refresh_interval_seconds"`
}

// ObservationState reports recorded coordinator state, never a reconstructed
// workflow phase or a claim that hardware has been independently verified.
type ObservationState struct {
	SchemaVersion        string                  `json:"schema_version"`
	StationID            string                  `json:"station_id"`
	LaneID               string                  `json:"lane_id"`
	TransactionID        string                  `json:"transaction_id"`
	ReadStatus           string                  `json:"read_status"`
	ReadDetail           string                  `json:"read_detail"`
	Stale                bool                    `json:"stale"`
	LastAttemptedRead    time.Time               `json:"last_attempted_read"`
	LastSuccessfulRead   *time.Time              `json:"last_successful_read,omitempty"`
	Snapshot             *TransactionObservation `json:"snapshot,omitempty"`
	LocalPorts           LocalPortObservations   `json:"local_ports"`
	UnresolvedConditions []string                `json:"unresolved_conditions"`
	NextAction           string                  `json:"next_action"`
}

type TransactionObservation struct {
	ID                string                              `json:"id"`
	ResourceVersion   uint64                              `json:"resource_version"`
	Status            controlplane.TransactionStatus      `json:"status"`
	StatusLabel       string                              `json:"status_label"`
	UpdatedAt         time.Time                           `json:"updated_at"`
	AssetID           string                              `json:"asset_id"`
	IntendedLogicalID string                              `json:"intended_logical_id"`
	ProfileID         string                              `json:"profile_id"`
	ActiveClaim       *ClaimObservation                   `json:"active_claim,omitempty"`
	ClaimHistory      []ClaimObservation                  `json:"claim_history"`
	RecordedPrestate  *controlplane.TargetBinding         `json:"recorded_prestate,omitempty"`
	Expected          ExpectedBindings                    `json:"expected"`
	Approval          *controlplane.Approval              `json:"approval,omitempty"`
	Operations        []OperationObservation              `json:"operations"`
	Quarantine        *controlplane.QuarantineRecord      `json:"quarantine,omitempty"`
	SecurityApplied   *controlplane.SecurityAppliedRecord `json:"security_applied,omitempty"`
	Abort             *controlplane.AbortRecord           `json:"abort,omitempty"`
	Hardware          HardwareUnknowns                    `json:"hardware"`
	EvidenceBasis     string                              `json:"evidence_basis"`
	FleetAdmission    string                              `json:"fleet_admission"`
}

type ClaimObservation struct {
	ID         string                   `json:"id"`
	StationID  string                   `json:"station_id"`
	LaneID     string                   `json:"lane_id"`
	Mode       controlplane.ClaimMode   `json:"mode"`
	Status     controlplane.ClaimStatus `json:"status"`
	FenceEpoch uint64                   `json:"fence_epoch"`
	AcquiredAt time.Time                `json:"acquired_at"`
	ExpiresAt  time.Time                `json:"expires_at"`
	ClosedAt   *time.Time               `json:"closed_at,omitempty"`
}

type ExpectedBindings struct {
	CustomerKeyHash         string                  `json:"customer_key_hash"`
	PrestateCustomerKeyHash string                  `json:"prestate_customer_key_hash"`
	BundleDigest            string                  `json:"bundle_digest"`
	PolicyDigest            string                  `json:"policy_digest"`
	TransactionDigest       string                  `json:"transaction_digest"`
	Release                 *releasebinding.Binding `json:"release,omitempty"`
}

type OperationObservation struct {
	Sequence                     int        `json:"sequence"`
	Operation                    string     `json:"operation"`
	Label                        string     `json:"label"`
	Status                       string     `json:"status"`
	StatusLabel                  string     `json:"status_label"`
	RecordID                     string     `json:"record_id,omitempty"`
	IntentAt                     *time.Time `json:"intent_at,omitempty"`
	EvidenceAt                   *time.Time `json:"evidence_at,omitempty"`
	IntentAuditReceiptID         string     `json:"intent_audit_receipt_id,omitempty"`
	EvidenceAuditReceiptID       string     `json:"evidence_audit_receipt_id,omitempty"`
	ReconciliationAuditReceiptID string     `json:"reconciliation_audit_receipt_id,omitempty"`
	InputDigest                  string     `json:"input_digest,omitempty"`
	PrestateDigest               string     `json:"prestate_digest,omitempty"`
	OutputDigest                 string     `json:"output_digest,omitempty"`
	ObservationDigest            string     `json:"observation_digest,omitempty"`
}

type HardwareUnknowns struct {
	CustomerKey           string `json:"customer_key"`
	SecureBoot            string `json:"secure_boot"`
	JTAG                  string `json:"jtag"`
	EEPROMWriteProtection string `json:"eeprom_write_protection"`
}

type LocalPortObservations struct {
	ObservedAt time.Time       `json:"observed_at"`
	USB        PortObservation `json:"usb"`
	UART       PortObservation `json:"uart"`
	Detail     string          `json:"detail"`
}

type PortObservation struct {
	Path      string `json:"path"`
	Status    string `json:"status"`
	VendorID  string `json:"vendor_id,omitempty"`
	ProductID string `json:"product_id,omitempty"`
}
