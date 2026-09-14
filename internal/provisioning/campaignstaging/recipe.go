package campaignstaging

import (
	"errors"
	"fmt"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
)

type writeRecipe struct {
	role                     string
	offset, size, sourceSize uint64
	sourceDigest, sha256     bundle.Digest
	path                     string
	data                     []byte
}
type recipe struct {
	configDigest, planDigest, requirementsDigest bundle.Digest
	identity                                     campaignmedia.DeviceIdentity
	backups                                      []Range
	writes                                       []writeRecipe
	envelope                                     *campaignmedia.InitialGPTRecoveryEnvelopeV1Alpha2
}

func derive(c Config) (recipe, error) {
	if err := c.Requirements.ValidateAgainst(c.Plan, c.Envelopes); err != nil {
		return recipe{}, fmt.Errorf("independent campaign bindings: %w", err)
	}
	index := -1
	for i, d := range c.Plan.Devices {
		if d.Identity.Leg == c.Leg {
			index = i
		}
	}
	if index < 0 {
		return recipe{}, errors.New("selected leg absent from campaign plan")
	}
	d := c.Plan.Devices[index]
	if len(c.Payloads) != len(d.Partitions) {
		return recipe{}, errors.New("payload paths must contain exactly the selected leg's partition roles")
	}
	r := recipe{configDigest: digest("candidate-campaign-staging-config/v1alpha1", c), planDigest: c.Plan.PlanDigest, requirementsDigest: c.Requirements.RecoveryRequirementsDigest, identity: d.Identity, envelope: &c.Envelopes[index]}
	seen := map[string]bool{}
	for _, p := range d.Partitions {
		path := c.Payloads[p.Role]
		if !canonicalPath(path) || seen[path] {
			return recipe{}, errors.New("payload paths must be distinct canonical absolute paths")
		}
		seen[path] = true
		r.writes = append(r.writes, writeRecipe{role: string(p.Role), offset: p.ByteStart, size: p.CapacityBytes, sourceSize: p.SourceSizeBytes, sourceDigest: p.SourceSHA256, sha256: p.ExpectedWholePartitionSHA256, path: path})
	}
	gpt, err := campaignmedia.FinalGPTWrites(d)
	if err != nil {
		return recipe{}, err
	}
	for _, g := range gpt {
		r.writes = append(r.writes, writeRecipe{role: string(g.Role), offset: g.Range.OffsetBytes, size: g.Range.SizeBytes, sourceSize: g.Range.SizeBytes, sourceDigest: g.Range.SHA256, sha256: g.Range.SHA256, data: g.Data})
	}
	for i, b := range c.Envelopes[index].RecoveryRanges {
		r.backups = append(r.backups, Range{Role: fmt.Sprintf("recovery-range-%d", i), Name: fmt.Sprintf("backup-%d.img", i), Offset: b.OffsetBytes, Size: b.SizeBytes, SHA256: b.PreimageSHA256})
	}
	return r, validateRecipe(r)
}

func validateRecipe(r recipe) error {
	if r.identity.CapacityBytes == 0 || len(r.backups) == 0 || len(r.writes) == 0 {
		return errors.New("incomplete staging recipe")
	}
	writes := make([]Range, len(r.writes))
	for i, w := range r.writes {
		if w.sourceSize == 0 || w.sourceSize > w.size {
			return errors.New("invalid source extent")
		}
		if err := w.sourceDigest.Validate(); err != nil {
			return err
		}
		writes[i] = Range{Offset: w.offset, Size: w.size, SHA256: w.sha256}
	}
	for _, rs := range [][]Range{r.backups, writes} {
		for i, s := range rs {
			if err := checkedRange(s.Offset, s.Size); err != nil {
				return err
			}
			if s.Offset+s.Size > r.identity.CapacityBytes {
				return errors.New("recipe exceeds target capacity")
			}
			if err := s.SHA256.Validate(); err != nil {
				return err
			}
			for _, p := range rs[:i] {
				if s.Offset < p.Offset+p.Size && p.Offset < s.Offset+s.Size {
					return errors.New("recipe ranges overlap")
				}
			}
		}
	}
	for _, w := range writes {
		covered := false
		for _, b := range r.backups {
			if w.Offset >= b.Offset && w.Offset+w.Size <= b.Offset+b.Size {
				covered = true
			}
		}
		if !covered {
			return errors.New("write lacks complete verified recovery coverage")
		}
	}
	return nil
}

func matchRecipe(p Preview, r recipe) error {
	if p.ConfigDigest != r.configDigest || p.PlanDigest != r.planDigest || p.RecoveryRequirementsDigest != r.requirementsDigest || p.Leg != r.identity.Leg || p.Attachment.SizeBytes != r.identity.CapacityBytes || p.Attachment.RequestedPath != r.identity.Selector || len(p.Backups) != len(r.backups) || len(p.Writes) != len(r.writes) {
		return errors.New("prepared record differs from independent configuration")
	}
	for i, b := range p.Backups {
		want := r.backups[i]
		if b.Role != want.Role || b.Name != want.Name || b.Offset != want.Offset || b.Size != want.Size || b.SHA256 != want.SHA256 {
			return errors.New("prepared recovery range differs from independent configuration")
		}
	}
	for i, w := range p.Writes {
		want := r.writes[i]
		if w.Name != fmt.Sprintf("source-%d.img", i) || w.Role != want.role || w.Offset != want.offset || w.Size != want.size || w.SHA256 != want.sha256 {
			return errors.New("prepared write range differs from independent configuration")
		}
	}
	return nil
}
