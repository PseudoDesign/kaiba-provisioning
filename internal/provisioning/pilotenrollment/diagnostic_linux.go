//go:build linux

package pilotenrollment

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"regexp"
)

var diagnosticKey = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var diagnosticDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type DiagnosticSubmission struct {
	Reference Ref `json:"reference"`
}
type DiagnosticReceipt struct {
	Instance string `json:"instance_id"`
	Digest   string `json:"receipt_digest"`
}

// SubmitDiagnostic sends a reference only. The URI is never fetched. Callers
// retain the exact input and key to reconcile/retry an ambiguous submission.
// It does not change the local credential state or claim full qualification.
func (c *Client) SubmitDiagnostic(ctx context.Context, input []byte, key string) (DiagnosticReceipt, error) {
	if c.value.Phase != "verified" || c.value.Bootstrap == nil {
		return DiagnosticReceipt{}, ErrState
	}
	var submission DiagnosticSubmission
	if len(input) > 4096 || decode(input, &submission) != nil || !diagnosticKey.MatchString(key) {
		return DiagnosticReceipt{}, ErrInput
	}
	ref := submission.Reference
	uri, err := url.Parse(ref.URI)
	if err != nil || !uri.IsAbs() || len(ref.URI) == 0 || len(ref.URI) > 2048 || !diagnosticDigest.MatchString(ref.Digest) {
		return DiagnosticReceipt{}, ErrInput
	}
	body := canon(submission)
	if len(body) > 4096 {
		return DiagnosticReceipt{}, ErrInput
	}
	raw, err := c.requestKey(ctx, "POST", "/api/v1/pilot/diagnostic-references", body, key)
	if err != nil {
		return DiagnosticReceipt{}, err
	}
	var receipt DiagnosticReceipt
	expected := fmt.Sprintf("sha256:%x", sha256.Sum256(body))
	if decode(raw, &receipt) != nil || receipt.Instance != c.value.Bootstrap.Enrollment || receipt.Digest != expected {
		return DiagnosticReceipt{}, &RequestError{Kind: "invalid_response", HTTPStatus: 200}
	}
	return receipt, nil
}
