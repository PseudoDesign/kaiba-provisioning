package pilotenrollment

import "encoding/json"

type renewalMetadata struct {
	Contract    string `json:"contract"`
	Version     string `json:"contract_version"`
	ID          string `json:"record_id"`
	Revision    uint64 `json:"revision"`
	Issued      string `json:"issued_at"`
	Authority   string `json:"authority_id"`
	Tenant      string `json:"tenant_id"`
	Domain      string `json:"security_domain_id"`
	Correlation string `json:"correlation_id"`
}
type renewalSelection struct {
	Handle string    `json:"handle"`
	Ref    RecordRef `json:"ref"`
}
type renewalRecords struct {
	Adoption renewalSelection `json:"adoption"`
	Policy   renewalSelection `json:"policy"`
	Decision renewalSelection `json:"decision"`
}
type renewalRequest struct {
	Operation   string         `json:"operation_id"`
	Records     renewalRecords `json:"records"`
	Expires     string         `json:"expires_at"`
	Predecessor RecordRef      `json:"predecessor_binding_ref"`
	Certificate string         `json:"predecessor_certificate_digest"`
}
type renewalAuthorization struct {
	renewalMetadata
	Mode        string    `json:"mode"`
	Operation   string    `json:"operation_id"`
	Logical     string    `json:"logical_device_id"`
	Instance    string    `json:"instance_id"`
	Storage     uint64    `json:"storage_generation"`
	Target      Target    `json:"target"`
	Adoption    RecordRef `json:"adoption_ref"`
	Policy      RecordRef `json:"policy_ref"`
	Admission   RecordRef `json:"admission_ref"`
	Audience    string    `json:"audience"`
	Profile     string    `json:"profile"`
	Permissions []string  `json:"permissions"`
	Full        bool      `json:"full_qualification"`
	Predecessor RecordRef `json:"predecessor_binding_ref"`
	Certificate string    `json:"predecessor_certificate_digest"`
	Previous    uint64    `json:"predecessor_credential_revision"`
	Next        uint64    `json:"successor_credential_revision"`
	Slot        string    `json:"credential_slot"`
	Generation  uint64    `json:"key_generation"`
	SPKI        string    `json:"spki_digest"`
	Issuer      string    `json:"issuer_id"`
	From        string    `json:"valid_from"`
	Expires     string    `json:"expires_at"`
}
type renewalKeyChallenge struct {
	Schema        string    `json:"schema_version"`
	Purpose       string    `json:"purpose"`
	Operation     string    `json:"operation_id"`
	Enrollment    string    `json:"enrollment_id"`
	Authorization RecordRef `json:"authorization_ref"`
	Certificate   string    `json:"predecessor_certificate_digest"`
	Nonce         string    `json:"nonce"`
	Issued        string    `json:"issued_at"`
	Expires       string    `json:"expires_at"`
}
type renewalApproval struct {
	Request       renewalRequest       `json:"request"`
	Authorization renewalAuthorization `json:"authorization"`
	Challenge     renewalKeyChallenge  `json:"challenge"`
	State         string               `json:"state"`
	Signature     string               `json:"signature,omitempty"`
	Verified      string               `json:"verified_at,omitempty"`
}
type renewalActivation struct {
	At      string    `json:"activated_at"`
	Receipt Ref       `json:"verifier_receipt_ref"`
	Policy  RecordRef `json:"policy_ref"`
	Restart string    `json:"restart_kind"`
}
type renewalBinding struct {
	RecoveryRef *RecordRef `json:"recovery_authorization_ref,omitempty"`
	renewalMetadata
	Logical            string             `json:"logical_device_id"`
	Instance           string             `json:"instance_id"`
	Storage            uint64             `json:"storage_generation"`
	Bootstrap          Ref                `json:"bootstrap_identity_ref"`
	Credential         credential         `json:"credential"`
	State              string             `json:"state"`
	Target             Target             `json:"target"`
	Adoption           RecordRef          `json:"adoption_ref"`
	Admission          RecordRef          `json:"admission_ref"`
	Policy             RecordRef          `json:"policy_ref"`
	Audience           string             `json:"audience"`
	Profile            string             `json:"profile"`
	Permissions        []string           `json:"permissions"`
	Full               bool               `json:"full_qualification"`
	Activation         *renewalActivation `json:"activation,omitempty"`
	Supersedes         *RecordRef         `json:"supersedes,omitempty"`
	CredentialRevision uint64             `json:"credential_revision,omitempty"`
	CertificateDigest  string             `json:"certificate_digest,omitempty"`
	RenewalRef         *RecordRef         `json:"renewal_authorization_ref,omitempty"`
	PredecessorRef     *RecordRef         `json:"predecessor_binding_ref,omitempty"`
	InstallationRef    *RecordRef         `json:"installation_receipt_ref,omitempty"`
}
type renewalInstallFields struct {
	Purpose       string    `json:"purpose"`
	Operation     string    `json:"operation_id"`
	Authorization RecordRef `json:"authorization_ref"`
	Predecessor   RecordRef `json:"predecessor_binding_ref"`
	Staged        RecordRef `json:"staged_binding_ref"`
	Certificate   string    `json:"certificate_digest"`
	Nonce         string    `json:"nonce"`
	Issued        string    `json:"challenge_issued_at"`
	Expires       string    `json:"challenge_expires_at"`
	Restart       string    `json:"restart_kind"`
}
type renewalInstallChallenge struct {
	renewalInstallFields
	Tenant string `json:"tenant_id"`
	Domain string `json:"security_domain_id"`
}
type renewalInstallReceipt struct {
	renewalMetadata
	renewalInstallFields
	Full     bool   `json:"full_qualification"`
	Proof    Ref    `json:"proof_ref"`
	Verified string `json:"verified_at"`
}
type renewalInstallation struct {
	State       string                   `json:"state"`
	Approval    renewalApproval          `json:"approval"`
	Predecessor response                 `json:"predecessor"`
	Certificate string                   `json:"certificate"`
	Staged      renewalBinding           `json:"staged_binding"`
	Challenge   *renewalInstallChallenge `json:"challenge,omitempty"`
	Signature   string                   `json:"signature,omitempty"`
	Receipt     *renewalInstallReceipt   `json:"receipt,omitempty"`
	Active      *renewalBinding          `json:"active_binding,omitempty"`
}
type renewalState struct {
	Phase            string                   `json:"phase"`
	PreparedAt       string                   `json:"prepared_at"`
	Approval         renewalApproval          `json:"approval"`
	Predecessor      renewalBinding           `json:"predecessor"`
	Proof            string                   `json:"key_proof"`
	Certificate      string                   `json:"certificate,omitempty"`
	Staged           *renewalBinding          `json:"staged_binding,omitempty"`
	InstalledProcess string                   `json:"installed_process,omitempty"`
	Challenge        *renewalInstallChallenge `json:"challenge,omitempty"`
	Signature        string                   `json:"signature,omitempty"`
	Receipt          *renewalInstallReceipt   `json:"receipt,omitempty"`
	Active           *renewalBinding          `json:"active_binding,omitempty"`
}
type RenewalStatus struct {
	Operation   string `json:"operation_id"`
	Phase       string `json:"phase"`
	Revision    uint64 `json:"credential_revision"`
	Certificate string `json:"certificate_digest,omitempty"`
}
type renewalSelf struct {
	Authorized string          `json:"authorized"`
	Instance   string          `json:"instance_id"`
	Binding    json.RawMessage `json:"binding"`
	Full       bool            `json:"full_qualification"`
}
