package campaignsandbox

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"
	"unicode/utf16"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/campaignmedia"
)

type writeRecipe struct {
	role                     string
	offset, size, sourceSize uint64
	sourceDigest, digest     bundle.Digest
	data                     []byte // GPT is derived from the typed final layout, never opaque input.
}

type diskRecipe struct {
	leg     campaignmedia.Leg
	size    uint64
	backups []Range
	writes  []writeRecipe
}

type recipe struct {
	planDigest, requirementsDigest bundle.Digest
	disks                          []diskRecipe
}

func derive(input Input) (recipe, error) {
	if err := input.Requirements.ValidateAgainst(input.Plan, input.Envelopes); err != nil {
		return recipe{}, fmt.Errorf("validate independent recovery contracts: %w", err)
	}
	r := recipe{planDigest: input.Plan.PlanDigest, requirementsDigest: input.Requirements.RecoveryRequirementsDigest}
	for i, device := range input.Plan.Devices {
		d := diskRecipe{leg: device.Identity.Leg, size: device.Identity.CapacityBytes}
		for j, span := range input.Envelopes[i].RecoveryRanges {
			d.backups = append(d.backups, Range{Name: fmt.Sprintf("backup-%d-%d.img", i, j), Offset: span.OffsetBytes, Size: span.SizeBytes, SHA256: span.PreimageSHA256})
		}
		for _, p := range device.Partitions {
			d.writes = append(d.writes, writeRecipe{role: string(p.Role), offset: p.ByteStart, size: p.CapacityBytes, sourceSize: p.SourceSizeBytes, sourceDigest: p.SourceSHA256, digest: p.ExpectedWholePartitionSHA256})
		}
		gpt, err := canonicalGPT(device)
		if err != nil {
			return recipe{}, err
		}
		for _, item := range gpt {
			if bundle.Sum(item.data) != item.digest {
				return recipe{}, fmt.Errorf("plan %s GPT digest does not match independently generated canonical bytes", item.role)
			}
			d.writes = append(d.writes, item)
		}
		r.disks = append(r.disks, d)
	}
	return r, validateRecipe(r)
}

func validateRecipe(r recipe) error {
	if len(r.disks) == 0 {
		return errors.New("empty synthetic recipe")
	}
	for _, d := range r.disks {
		if d.size == 0 || len(d.backups) == 0 || len(d.writes) == 0 {
			return errors.New("incomplete synthetic recipe")
		}
		for _, ranges := range [][]Range{d.backups, writeRanges(d)} {
			for i, span := range ranges {
				if err := checkedRange(span.Offset, span.Size); err != nil {
					return err
				}
				if span.Offset+span.Size > d.size {
					return errors.New("range outside synthetic disk")
				}
				for _, prior := range ranges[:i] {
					if span.Offset < prior.Offset+prior.Size && prior.Offset < span.Offset+span.Size {
						return errors.New("overlapping synthetic ranges")
					}
				}
			}
		}
		for _, w := range d.writes {
			if w.sourceSize == 0 || w.sourceSize > w.size {
				return errors.New("invalid source size")
			}
			covered := false
			for _, b := range d.backups {
				if w.offset >= b.Offset && w.offset+w.size <= b.Offset+b.Size {
					covered = true
				}
			}
			if !covered {
				return errors.New("a write is not wholly covered by one verified recovery range")
			}
		}
	}
	return nil
}

func writeRanges(d diskRecipe) []Range {
	var result []Range
	for _, w := range d.writes {
		result = append(result, Range{Offset: w.offset, Size: w.size, SHA256: w.digest})
	}
	return result
}

func guidBytes(guid string) ([]byte, error) {
	b, err := hex.DecodeString(strings.ReplaceAll(guid, "-", ""))
	if err != nil || len(b) != 16 {
		return nil, errors.New("invalid GPT GUID")
	}
	b[0], b[1], b[2], b[3] = b[3], b[2], b[1], b[0]
	b[4], b[5] = b[5], b[4]
	b[6], b[7] = b[7], b[6]
	return b, nil
}

// canonicalGPT independently derives all semantic fields, unused entries,
// padding, CRCs and reciprocal headers. The plan must bind exactly these bytes.
func canonicalGPT(device campaignmedia.DevicePlan) ([]writeRecipe, error) {
	entries := make([]byte, 128*128)
	for _, p := range device.Partitions {
		if p.Number == 0 || p.Number > 128 || p.CapacityBytes == 0 || p.ByteStart%512 != 0 || p.CapacityBytes%512 != 0 {
			return nil, errors.New("invalid canonical GPT partition")
		}
		e := entries[(p.Number-1)*128 : p.Number*128]
		t, err := guidBytes(p.TypeGUID)
		if err != nil {
			return nil, err
		}
		copy(e[:16], t)
		u, err := guidBytes(p.UniqueGUID)
		if err != nil {
			return nil, err
		}
		copy(e[16:32], u)
		binary.LittleEndian.PutUint64(e[32:40], p.ByteStart/512)
		binary.LittleEndian.PutUint64(e[40:48], (p.ByteStart+p.CapacityBytes)/512-1)
		binary.LittleEndian.PutUint64(e[48:56], p.GPTAttributes)
		name := utf16.Encode([]rune(p.GPTName))
		if len(name) > 36 {
			return nil, errors.New("GPT name too long")
		}
		for i, c := range name {
			binary.LittleEndian.PutUint16(e[56+i*2:58+i*2], c)
		}
	}
	diskGUID, err := guidBytes(device.Identity.DiskGUID)
	if err != nil {
		return nil, err
	}
	header := func(current, alternate, array uint64) []byte {
		b := make([]byte, 512)
		copy(b, []byte("EFI PART"))
		binary.LittleEndian.PutUint32(b[8:12], 0x10000)
		binary.LittleEndian.PutUint32(b[12:16], 92)
		binary.LittleEndian.PutUint64(b[24:32], current)
		binary.LittleEndian.PutUint64(b[32:40], alternate)
		binary.LittleEndian.PutUint64(b[40:48], device.GPT.FirstUsableLBA)
		binary.LittleEndian.PutUint64(b[48:56], device.GPT.LastUsableLBA)
		copy(b[56:72], diskGUID)
		binary.LittleEndian.PutUint64(b[72:80], array)
		binary.LittleEndian.PutUint32(b[80:84], 128)
		binary.LittleEndian.PutUint32(b[84:88], 128)
		binary.LittleEndian.PutUint32(b[88:92], crc32.ChecksumIEEE(entries))
		binary.LittleEndian.PutUint32(b[16:20], crc32.ChecksumIEEE(b[:92]))
		return b
	}
	mbr := make([]byte, 512)
	mbr[446+4] = 0xee
	binary.LittleEndian.PutUint32(mbr[454:458], 1)
	if device.GPT.ProtectiveMBRLastLBA > 0xffffffff {
		return nil, errors.New("PMBR capacity exceeds fixed campaign range")
	}
	binary.LittleEndian.PutUint32(mbr[458:462], uint32(device.GPT.ProtectiveMBRLastLBA))
	mbr[510] = 0x55
	mbr[511] = 0xaa
	items := []struct {
		role string
		span campaignmedia.ByteRangeDigest
		data []byte
	}{
		{string(campaignmedia.GPTBackupEntryArray), device.GPT.BackupEntryArray, entries},
		{string(campaignmedia.GPTBackupHeader), device.GPT.BackupHeader, header(device.GPT.BackupHeaderLBA, 1, device.GPT.BackupEntryArrayLBA)},
		{string(campaignmedia.GPTPrimaryEntryArray), device.GPT.PrimaryEntryArray, entries},
		{string(campaignmedia.GPTPrimaryHeader), device.GPT.PrimaryHeader, header(1, device.GPT.BackupHeaderLBA, 2)},
		{string(campaignmedia.GPTProtectiveMBR), device.GPT.ProtectiveMBR, mbr},
	}
	var result []writeRecipe
	for _, x := range items {
		result = append(result, writeRecipe{role: x.role, offset: x.span.OffsetBytes, size: x.span.SizeBytes, sourceSize: uint64(len(x.data)), sourceDigest: bundle.Sum(x.data), digest: x.span.SHA256, data: x.data})
	}
	return result, nil
}
