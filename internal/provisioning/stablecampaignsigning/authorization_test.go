package stablecampaignsigning

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signingapproval"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signinggate"
)

const (
	testApprovedAt = "2026-08-18T12:00:00Z"
	testExpiresAt  = "2026-08-18T16:00:00Z"
)

func TestNewAuthorizationIsDeterministicAndExactlyOneGrant(t *testing.T) {
	intent := testIntent(t)
	first, err := NewAuthorization(intent, "reviewer:alice", testApprovedAt, testExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewAuthorization(intent, "reviewer:alice", testApprovedAt, testExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	firstApproval, err := first.Approval.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	secondApproval, _ := second.Approval.CanonicalJSON()
	firstRegistry, err := signingapproval.CanonicalRegistryJSON(first.Registry)
	if err != nil {
		t.Fatal(err)
	}
	secondRegistry, _ := signingapproval.CanonicalRegistryJSON(second.Registry)
	if !bytes.Equal(firstApproval, secondApproval) || !bytes.Equal(firstRegistry, secondRegistry) {
		t.Fatal("identical review inputs did not produce byte-identical authorization")
	}
	if len(first.Registry.Grants) != 1 {
		t.Fatalf("grant count = %d, want 1", len(first.Registry.Grants))
	}
	if first.Approval.ApprovalID != "approval:"+strings.TrimPrefix(string(first.Approval.ApprovalDigest), "sha256:") {
		t.Fatalf("approval ID is not digest-derived: %q", first.Approval.ApprovalID)
	}
	if bundle.Sum(firstApproval) == first.Approval.ApprovalDigest {
		t.Fatal("approval digest is not domain-separated")
	}
	intentDigest, _ := intent.Digest()
	grant := first.Registry.Grants[0]
	if grant.ExpiresAt != testExpiresAt || grant.Request.Role != bundle.RoleBootImage || grant.Request.ArtifactDigest != intent.SigningInput.Digest {
		t.Fatalf("grant does not identify exact boot input: %#v", grant)
	}
	if grant.Request.Algorithm != signing.AlgorithmRSA2048SHA256 || grant.Request.Approval.ApprovalID != first.Approval.ApprovalID || grant.Request.Approval.ApprovalDigest != first.Approval.ApprovalDigest || grant.Request.Approval.ReleaseIntentDigest != intentDigest || grant.Request.Approval.Role != bundle.RoleBootImage || grant.Request.Approval.ArtifactDigest != intent.SigningInput.Digest {
		t.Fatalf("grant has incomplete stable approval binding: %#v", grant.Request)
	}
	parsedApproval, err := ParseApproval(append(firstApproval, '\n'))
	if err != nil {
		t.Fatal(err)
	}
	parsedRegistry, err := signingapproval.ParseRegistry(append(firstRegistry, '\n'))
	if err != nil {
		t.Fatal(err)
	}
	if err := (Authorization{Approval: parsedApproval, Registry: parsedRegistry}).Validate(intent); err != nil {
		t.Fatalf("canonical round trip failed: %v", err)
	}
}

func TestAuthorizationTimesAndCurrentWindowAreClosed(t *testing.T) {
	intent := testIntent(t)
	tests := []struct {
		name       string
		reviewer   string
		approvedAt string
		expiresAt  string
		match      string
	}{
		{"missing reviewer", "", testApprovedAt, testExpiresAt, "reviewer_id"},
		{"ambiguous reviewer", "Reviewer Alice", testApprovedAt, testExpiresAt, "reviewer_id"},
		{"fractional approved", "reviewer:alice", "2026-08-18T12:00:00.000Z", testExpiresAt, "approved_at"},
		{"offset expiry", "reviewer:alice", testApprovedAt, "2026-08-18T12:30:00-04:00", "expires_at"},
		{"same expiry", "reviewer:alice", testApprovedAt, testApprovedAt, "after approved_at"},
		{"over 24 hours", "reviewer:alice", testApprovedAt, "2026-08-19T12:00:01Z", "24 hours"},
		{"before source", "reviewer:alice", "2026-08-16T12:00:00Z", "2026-08-16T13:00:00Z", "source_date_epoch"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewAuthorization(intent, test.reviewer, test.approvedAt, test.expiresAt)
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("NewAuthorization() error = %v, want match %q", err, test.match)
			}
		})
	}
	authorization, err := NewAuthorization(intent, "reviewer:alice", testApprovedAt, testExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		now   string
		match string
	}{
		{"future", "2026-08-18T11:59:59Z", "future"},
		{"expired", testExpiresAt, "expired"},
	} {
		t.Run(test.name, func(t *testing.T) {
			now, _ := time.Parse(time.RFC3339, test.now)
			err := authorization.Approval.RequireCurrentlyActive(now)
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("RequireCurrentlyActive() error = %v, want match %q", err, test.match)
			}
		})
	}
	now, _ := time.Parse(time.RFC3339, "2026-08-18T13:00:00Z")
	if err := authorization.Approval.RequireCurrentlyActive(now); err != nil {
		t.Fatalf("active approval rejected: %v", err)
	}
}

func TestAuthorizationRejectsManualOrBroadenedRegistry(t *testing.T) {
	intent := testIntent(t)
	valid, err := NewAuthorization(intent, "reviewer:alice", testApprovedAt, testExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		match string
		alter func(*Authorization)
	}{
		{"no grant", "between 1", func(value *Authorization) { value.Registry.Grants = nil }},
		{"manual grant ID", "exact deterministic", func(value *Authorization) { value.Registry.Grants[0].GrantID = "grant:manual" }},
		{"manual request ID", "exact deterministic", func(value *Authorization) { value.Registry.Grants[0].Request.RequestID = "request:manual" }},
		{"different expiry", "exact deterministic", func(value *Authorization) { value.Registry.Grants[0].ExpiresAt = "2026-08-18T15:00:00Z" }},
		{"different approval digest", "exact deterministic", func(value *Authorization) { value.Registry.Grants[0].Request.Approval.ApprovalDigest = testDigest("f") }},
		{"extra grant", "exact deterministic", func(value *Authorization) {
			extra := value.Registry.Grants[0]
			extra.GrantID = "grant:z"
			extra.Request.RequestID = "request:z"
			value.Registry.Grants = append(value.Registry.Grants, extra)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneAuthorization(t, valid)
			test.alter(&candidate)
			err := candidate.Validate(intent)
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("Validate() error = %v, want match %q", err, test.match)
			}
		})
	}

	different := intent
	different.SigningInput.Digest = testDigest("f")
	if err := valid.Validate(different); err == nil || !strings.Contains(err.Error(), "supplied stable signing intent") {
		t.Fatalf("different intent error = %v", err)
	}
}

func TestApprovalStrictCanonicalJSON(t *testing.T) {
	valid, err := NewAuthorization(testIntent(t), "reviewer:alice", testApprovedAt, testExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := valid.Approval.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	canonical := string(encoded)
	for _, test := range []struct {
		name  string
		input string
		match string
	}{
		{"unknown", strings.Replace(canonical, `"decision"`, `"unknown":true,"decision"`, 1), "unknown field"},
		{"duplicate", strings.Replace(canonical, `"decision":"approved"`, `"decision":"approved","decision":"approved"`, 1), "duplicated"},
		{"null", strings.Replace(canonical, `"reviewer_id":"reviewer:alice"`, `"reviewer_id":null`, 1), "null"},
		{"leading whitespace", " " + canonical, "canonical"},
		{"second newline", canonical + "\n\n", "canonical"},
		{"trailing", canonical + `{}`, "trailing"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseApproval([]byte(test.input))
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("ParseApproval() error = %v, want match %q", err, test.match)
			}
		})
	}
}

func TestOneGrantGateResolutionIsUnambiguous(t *testing.T) {
	authorization, err := NewAuthorization(testIntent(t), "reviewer:alice", testApprovedAt, testExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	now, _ := time.Parse(time.RFC3339, "2026-08-18T13:00:00Z")
	grant, err := authorization.Registry.CurrentGrant(authorization.Approval.SigningInput.Digest, now)
	if err != nil {
		t.Fatal(err)
	}
	if grant.Request.Role != bundle.RoleBootImage {
		t.Fatalf("resolved role = %q", grant.Request.Role)
	}
	expired, _ := time.Parse(time.RFC3339, testExpiresAt)
	if _, err := authorization.Registry.CurrentGrant(authorization.Approval.SigningInput.Digest, expired); err == nil || !strings.Contains(err.Error(), "no current") {
		t.Fatalf("expired CurrentGrant() error = %v", err)
	}
}

func cloneAuthorization(t *testing.T, value Authorization) Authorization {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var clone struct {
		Approval Approval             `json:"Approval"`
		Registry signinggate.Registry `json:"Registry"`
	}
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	return Authorization{Approval: clone.Approval, Registry: clone.Registry}
}
