package campaignmedia

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"
	"unicode/utf16"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

// FinalGPTWrite contains independently generated canonical bytes for one
// final GPT range. Ordering is backup entries/header, primary entries/header,
// then protective MBR. This pure derivation confers no device write authority.
type FinalGPTWrite struct {
	Role  GPTRegionRole
	Range ByteRangeDigest
	Data  []byte
}

func finalGPTGUIDBytes(guid string) ([]byte, error) {
	b, err := hex.DecodeString(strings.ReplaceAll(guid, "-", ""))
	if err != nil || len(b) != 16 {
		return nil, errors.New("invalid GPT GUID")
	}
	b[0], b[1], b[2], b[3] = b[3], b[2], b[1], b[0]
	b[4], b[5] = b[5], b[4]
	b[6], b[7] = b[7], b[6]
	return b, nil
}

// FinalGPTWrites independently derives all semantic fields, unused entries,
// padding, CRCs and reciprocal headers. The plan must bind exactly these bytes.
func FinalGPTWrites(device DevicePlan) ([]FinalGPTWrite, error) {
	if err := device.Validate(); err != nil {
		return nil, err
	}
	entries := make([]byte, 128*128)
	for _, p := range device.Partitions {
		if p.Number == 0 || p.Number > 128 || p.CapacityBytes == 0 || p.ByteStart%512 != 0 || p.CapacityBytes%512 != 0 {
			return nil, errors.New("invalid canonical GPT partition")
		}
		e := entries[(p.Number-1)*128 : p.Number*128]
		t, err := finalGPTGUIDBytes(p.TypeGUID)
		if err != nil {
			return nil, err
		}
		copy(e[:16], t)
		u, err := finalGPTGUIDBytes(p.UniqueGUID)
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
	diskGUID, err := finalGPTGUIDBytes(device.Identity.DiskGUID)
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
		span ByteRangeDigest
		data []byte
	}{
		{string(GPTBackupEntryArray), device.GPT.BackupEntryArray, entries},
		{string(GPTBackupHeader), device.GPT.BackupHeader, header(device.GPT.BackupHeaderLBA, 1, device.GPT.BackupEntryArrayLBA)},
		{string(GPTPrimaryEntryArray), device.GPT.PrimaryEntryArray, entries},
		{string(GPTPrimaryHeader), device.GPT.PrimaryHeader, header(1, device.GPT.BackupHeaderLBA, 2)},
		{string(GPTProtectiveMBR), device.GPT.ProtectiveMBR, mbr},
	}
	var result []FinalGPTWrite
	for _, x := range items {
		if uint64(len(x.data)) != x.span.SizeBytes || bundle.Sum(x.data) != x.span.SHA256 {
			return nil, fmt.Errorf("final GPT %s bytes differ from staging plan", x.role)
		}
		result = append(result, FinalGPTWrite{Role: GPTRegionRole(x.role), Range: x.span, Data: append([]byte(nil), x.data...)})
	}
	return result, nil
}
