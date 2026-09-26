package pilotenrollment

type recoveryInstallation struct {
	State       string                   `json:"state"`
	Approval    recoveryApproval         `json:"approval"`
	Predecessor response                 `json:"predecessor"`
	Certificate string                   `json:"certificate"`
	Staged      renewalBinding           `json:"staged_binding"`
	Challenge   *renewalInstallChallenge `json:"challenge,omitempty"`
	Signature   string                   `json:"signature,omitempty"`
	Receipt     *renewalInstallReceipt   `json:"receipt,omitempty"`
	Active      *renewalBinding          `json:"active_binding,omitempty"`
}
type recoveryInstallState struct {
	Phase            string                   `json:"phase"`
	PreparedAt       string                   `json:"prepared_at"`
	Approval         recoveryApproval         `json:"approval"`
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
