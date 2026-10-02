package campaignqualification

import (
	"testing"
)

func TestCampaignRequiresExactlyOneFrozen33Run37ClaimReview(t *testing.T) {
	fixtures := []*fixture{}
	for index := uint16(1); index <= 33; index++ {
		fixtures = append(fixtures, newFixture(t, index))
	}
	policy := fixtures[0].policy
	for role := range policy.Keys {
		policy.Keys[role].Kinds = nil
		for kind := range witnessSources {
			policy.Keys[role].Kinds = append(policy.Keys[role].Kinds, kind)
		}
	}
	reports := []Report{}
	for _, f := range fixtures {
		f.policy, f.private = policy, fixtures[0].private
		f.sign(t)
		report, err := f.validate()
		if err != nil {
			t.Fatal(err)
		}
		reports = append(reports, report)
	}
	review, err := ReviewCampaign(fixtures[0].expectation.plan, reports)
	if err != nil {
		t.Fatal(err)
	}
	if review.value.ReviewedClaimCount != 37 || review.value.SecurityApplied || review.value.ProductionReady || review.value.EnrollmentReady {
		t.Fatal("wrong campaign coverage or overstated readiness")
	}
	if _, err := ReviewCampaign(fixtures[0].expectation.plan, reports[:32]); err == nil {
		t.Fatal("incomplete campaign accepted")
	}
	for _, mutate := range []func([]Report){func(r []Report) { r[1] = r[0] }, func(r []Report) { r[1].value.Session.DeviceFingerprint = digest("other-board") }, func(r []Report) { r[1].value.TrustPolicyDigest = digest("other-policy") }, func(r []Report) { r[1].value.Session.Context.CaptureID = r[0].value.Session.Context.CaptureID }} {
		copied := append([]Report(nil), reports...)
		mutate(copied)
		if _, err := ReviewCampaign(fixtures[0].expectation.plan, copied); err == nil {
			t.Fatal("detached campaign report accepted")
		}
	}
}
