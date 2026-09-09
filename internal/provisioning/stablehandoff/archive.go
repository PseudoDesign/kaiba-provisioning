// Package stablehandoff constructs the one-boot credential payload and loads
// a previously verified Linux release without reopening untrusted paths.
package stablehandoff

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
)

const (
	MaxAuthorizationBytes = 64 * 1024
	MaxDMVerityBytes      = 1024 * 1024
	MaxSlotMetadataBytes  = 4096
	MaxBaseInitramfsBytes = 512 * 1024 * 1024
)

// Credential is the complete ephemeral input passed from the stable verifier
// to the authorized second-stage initramfs. The private key must never be
// persisted outside the in-memory handoff image.
type Credential struct {
	Authorization     []byte
	OneBootPrivateKey ed25519.PrivateKey
	DMVerityMetadata  []byte
	SlotMetadata      []byte
}

// AppendCredentialArchive copies the already verified base initramfs and
// appends a fixed-format, uncompressed newc archive. Linux accepts concatenated
// initramfs archives and extracts the later archive over the earlier one.
func AppendCredentialArchive(destination io.Writer, base io.Reader, baseSize int64, credential Credential) error {
	if destination == nil || base == nil {
		return errors.New("destination and base initramfs are required")
	}
	if baseSize <= 0 || baseSize > MaxBaseInitramfsBytes {
		return fmt.Errorf("base initramfs size must be between 1 and %d bytes", MaxBaseInitramfsBytes)
	}
	if len(credential.Authorization) == 0 || len(credential.Authorization) > MaxAuthorizationBytes {
		return fmt.Errorf("authorization size must be between 1 and %d bytes", MaxAuthorizationBytes)
	}
	if len(credential.OneBootPrivateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("one-boot private key must be exactly %d bytes", ed25519.PrivateKeySize)
	}
	if len(credential.DMVerityMetadata) == 0 || len(credential.DMVerityMetadata) > MaxDMVerityBytes {
		return fmt.Errorf("dm-verity metadata size must be between 1 and %d bytes", MaxDMVerityBytes)
	}
	if len(credential.SlotMetadata) == 0 || len(credential.SlotMetadata) > MaxSlotMetadataBytes {
		return fmt.Errorf("slot metadata size must be between 1 and %d bytes", MaxSlotMetadataBytes)
	}

	written, err := io.CopyN(destination, base, baseSize)
	if err != nil {
		return fmt.Errorf("copy verified base initramfs: %w", err)
	}
	if written != baseSize {
		return errors.New("verified base initramfs ended before its retained size")
	}
	var trailing [1]byte
	if count, readErr := base.Read(trailing[:]); readErr != io.EOF || count != 0 {
		if readErr != nil {
			return fmt.Errorf("check verified base initramfs boundary: %w", readErr)
		}
		return errors.New("verified base initramfs contains bytes beyond its retained size")
	}
	// Each raw cpio member starts on a four-byte boundary in the Linux
	// initramfs buffer grammar. A compressed base member may end at any byte, so
	// insert the permitted zero padding before the appended newc member.
	padding := (4 - baseSize%4) % 4
	if padding != 0 {
		written, err := destination.Write(make([]byte, padding))
		if err != nil {
			return fmt.Errorf("align appended credential archive: %w", err)
		}
		if int64(written) != padding {
			return fmt.Errorf("align appended credential archive: %w", io.ErrShortWrite)
		}
	}

	encodedKey, err := x509.MarshalPKCS8PrivateKey(credential.OneBootPrivateKey)
	if err != nil {
		return fmt.Errorf("encode one-boot private key: %w", err)
	}
	defer clear(encodedKey)
	entries := []cpioEntry{
		{name: "run", mode: 0040755},
		{name: "run/kaiba", mode: 0040700},
		{name: "run/kaiba/boot-authorization.json", mode: 0100400, contents: append([]byte(nil), credential.Authorization...)},
		{name: "run/kaiba/one-boot-ed25519.pk8", mode: 0100400, contents: encodedKey},
		{name: "run/kaiba/dm-verity.json", mode: 0100444, contents: append([]byte(nil), credential.DMVerityMetadata...)},
		{name: "run/kaiba/slot.txt", mode: 0100444, contents: append([]byte(nil), credential.SlotMetadata...)},
	}
	archive, err := buildNewc(entries)
	if err != nil {
		return err
	}
	defer clear(archive)
	if _, err := io.Copy(destination, bytes.NewReader(archive)); err != nil {
		return fmt.Errorf("append one-boot credential archive: %w", err)
	}
	return nil
}

type cpioEntry struct {
	name     string
	mode     uint32
	contents []byte
}

func buildNewc(entries []cpioEntry) ([]byte, error) {
	var output bytes.Buffer
	for index, entry := range entries {
		if entry.name == "" || entry.name[0] == '/' || bytes.IndexByte([]byte(entry.name), 0) >= 0 {
			return nil, fmt.Errorf("invalid archive entry name %q", entry.name)
		}
		if err := writeNewcEntry(&output, uint32(index+1), entry); err != nil {
			return nil, err
		}
	}
	if err := writeNewcEntry(&output, uint32(len(entries)+1), cpioEntry{name: "TRAILER!!!", mode: 0}); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func writeNewcEntry(destination *bytes.Buffer, inode uint32, entry cpioEntry) error {
	nameSize := len(entry.name) + 1
	header := fmt.Sprintf(
		"070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
		inode,
		entry.mode,
		0,
		0,
		1,
		0,
		len(entry.contents),
		0,
		0,
		0,
		0,
		nameSize,
		0,
	)
	if len(header) != 110 {
		return errors.New("construct newc header")
	}
	destination.WriteString(header)
	destination.WriteString(entry.name)
	destination.WriteByte(0)
	writePadding(destination, 110+nameSize)
	destination.Write(entry.contents)
	writePadding(destination, len(entry.contents))
	return nil
}

func writePadding(destination *bytes.Buffer, currentLength int) {
	padding := (4 - currentLength%4) % 4
	for range padding {
		destination.WriteByte(0)
	}
}
