package campaignqualification

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/stablecampaign"
)

type campaignRecord struct {
	SchemaVersion            string          `json:"schema_version"`
	Assurance                string          `json:"assurance"`
	CampaignID               string          `json:"campaign_id"`
	PlanDigest               bundle.Digest   `json:"plan_digest"`
	DeviceFingerprint        bundle.Digest   `json:"device_fingerprint"`
	ProfileDigest            bundle.Digest   `json:"profile_digest"`
	ArtifactSetContentDigest bundle.Digest   `json:"artifact_set_content_digest"`
	LayoutDigest             bundle.Digest   `json:"layout_digest"`
	TrustPolicyDigest        bundle.Digest   `json:"trust_policy_digest"`
	RunReportDigests         []bundle.Digest `json:"run_report_digests"`
	ReviewedClaimCount       int             `json:"reviewed_claim_count"`
	SecurityApplied          bool            `json:"security_applied"`
	ProductionReady          bool            `json:"production_ready"`
	EnrollmentReady          bool            `json:"enrollment_ready"`
	ReportDigest             bundle.Digest   `json:"report_digest,omitempty"`
}

type CampaignReport struct{ value campaignRecord }

func (report CampaignReport) CanonicalJSON() ([]byte, error) {
	if report.value.ReportDigest == "" {
		return nil, errors.New("uninitialized campaign review")
	}
	return json.Marshal(report.value)
}

// ReviewCampaign accepts only opaque reports returned by successful Validate
// calls, in exact run order, for one frozen board/profile/baseline/trust policy.
// Owned recovery, EEPROM/OTP readback, and seven-operation terminalization are
// separate gates; this review never asserts security_applied.
func ReviewCampaign(plan stablecampaign.Plan, reports []Report) (CampaignReport, error) {
	runs, err := stablecampaign.ExpectedRuns(plan)
	if err != nil {
		return CampaignReport{}, err
	}
	if len(reports) != len(runs) {
		return CampaignReport{}, errors.New("all 33 independently reviewed run reports are required")
	}
	first := reports[0].value
	record := campaignRecord{SchemaVersion: "kaiba.provisioning.rpi5-campaign-reviewed-set/v1alpha1", Assurance: "authenticated-independent-review-testimony",
		CampaignID: plan.CampaignID, PlanDigest: plan.PlanDigest, DeviceFingerprint: first.Session.DeviceFingerprint, ProfileDigest: first.Session.ProfileDigest,
		ArtifactSetContentDigest: first.ArtifactSetContentDigest, LayoutDigest: first.LayoutDigest, TrustPolicyDigest: first.TrustPolicyDigest}
	seen := map[stablecampaign.CaptureID]bool{}
	for index, report := range reports {
		value := report.value
		context := value.Session.Context
		if value.ReportDigest == "" || value.SchemaVersion != ReportSchema || value.Assurance != record.Assurance || context.CampaignID != plan.CampaignID || context.PlanDigest != plan.PlanDigest || context.RunIndex != runs[index].Index || context.RunID != runs[index].RunID || seen[context.CaptureID] ||
			value.Session.DeviceFingerprint != record.DeviceFingerprint || value.Session.ProfileDigest != record.ProfileDigest || value.ArtifactSetContentDigest != record.ArtifactSetContentDigest || value.LayoutDigest != record.LayoutDigest || value.TrustPolicyDigest != record.TrustPolicyDigest || !slices.Equal(value.ReviewedClaims, runs[index].PlannedClaims) {
			return CampaignReport{}, fmt.Errorf("run report %d is missing, reordered, replayed, or outside the frozen candidate", index+1)
		}
		seen[context.CaptureID] = true
		record.RunReportDigests = append(record.RunReportDigests, value.ReportDigest)
		record.ReviewedClaimCount += len(value.ReviewedClaims)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return CampaignReport{}, err
	}
	record.ReportDigest = domainDigest("kaiba.provisioning.rpi5-campaign-reviewed-set.v1alpha1", encoded)
	return CampaignReport{value: record}, nil
}
