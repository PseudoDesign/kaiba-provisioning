package pemmarkers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unsafe"
)

func scanChunks(t *testing.T, mode Mode, input []byte, size int) (Report, error) {
	t.Helper()
	scanner, err := New(mode)
	if err != nil {
		t.Fatal(err)
	}
	for len(input) > 0 {
		n := size
		if n > len(input) {
			n = len(input)
		}
		if err := scanner.Consume(input[:n]); err != nil {
			return Report{}, err
		}
		input = input[n:]
	}
	return scanner.Finish()
}

func TestStrictMarkersAcrossBoundaries(t *testing.T) {
	markers := []string{"-----BEGIN PRIVATE KEY-----", "-----BEGIN ENCRYPTED PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----", "-----BEGIN DSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN ML-DSA PRIVATE KEY-----", "-----BEGIN THIS-----PRIVATE KEY-----"}
	for _, marker := range markers {
		for split := 0; split <= len(marker); split++ {
			scanner, _ := New(Strict)
			first := []byte("unrelated binary\x00-------" + marker[:split])
			second := []byte(marker[split:] + "\x00")
			err := scanner.Consume(first)
			if err == nil {
				err = scanner.Consume(second)
			}
			if err == nil {
				_, err = scanner.Finish()
			}
			if !errors.Is(err, ErrPrivateKeyMarker) {
				t.Fatalf("marker split %d accepted or wrong error: %v", split, err)
			}
		}
	}
}

func TestReviewedPublicMarkerLiteralsAndStrictMetadata(t *testing.T) {
	for _, literal := range []string{"-----BEGIN PRIVATE KEY-----\x00", "-----BEGIN RSA PRIVATE KEY-----\x00", "-----BEGIN EC PRIVATE KEY-----\x00", "-----BEGIN ENCRYPTED PRIVATE KEY-----\x00", "-----BEGIN OPENSSH PRIVATE KEY-----\x00", "-----BEGIN OPENSSH PRIVATE KEY-----\n\x00"} {
		for split := 1; split <= len(literal); split++ {
			input := []byte("unrelated prefix\x00" + literal + "unrelated suffix")
			report, err := scanChunks(t, ReviewedRootLiterals, input, split)
			if err != nil || len(report.PublicLiteralMatches) != 1 || report.PublicLiteralMatches[0].Occurrences != 1 || report.BytesScanned != uint64(len(input)) {
				t.Fatalf("reviewed literal rejected at chunk %d: %v", split, err)
			}
			if _, err := scanChunks(t, Strict, input, split); !errors.Is(err, ErrPrivateKeyMarker) {
				t.Fatal("strict metadata accepted reviewed literal")
			}
		}
	}
}

func TestReviewedModeFailsClosed(t *testing.T) {
	known := []byte("-----BEGIN PRIVATE KEY-----\x00")
	unknown := []byte("-----BEGIN RSA PRIVATE KEY-----\nnot-a-public-fixture\n-----END RSA PRIVATE KEY-----\n\x00")
	inputs := map[string][]byte{
		"unknown complete":       unknown,
		"bare header":            []byte("-----BEGIN PRIVATE KEY-----"),
		"missing nul":            []byte("-----BEGIN PRIVATE KEY-----\n"),
		"added body":             []byte("-----BEGIN PRIVATE KEY-----secret body\x00"),
		"changed literal suffix": []byte("-----BEGIN OPENSSH PRIVATE KEY-----\r\x00"),
		"unknown after known":    append(append([]byte{}, known...), unknown...),
		"unknown before known":   append(append([]byte{}, unknown...), known...),
		"nested marker":          []byte("-----BEGIN PRIVATE KEY----------BEGIN PRIVATE KEY-----\x00"),
		"overlong literal":       append([]byte("-----BEGIN PRIVATE KEY-----"), bytes.Repeat([]byte{'a'}, MaxLiteralBytes)...),
		"overlong header":        []byte("-----BEGIN " + strings.Repeat("A", maxHeaderBytes) + " PRIVATE KEY-----\x00"),
		"unknown marker type":    []byte("-----BEGIN ML-DSA PRIVATE KEY-----\x00"),
	}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			for _, size := range []int{1, 7, 127, 16384} {
				if _, err := scanChunks(t, ReviewedRootLiterals, input, size); !errors.Is(err, ErrPrivateKeyMarker) {
					t.Fatalf("unexpected result: %v", err)
				}
			}
		})
	}
}

func TestPublicBeginTemplatesNeedAnActualPrivateSuffix(t *testing.T) {
	for _, input := range []string{
		"-----BEGIN CERTIFICATE----- -----BEGIN PUBLIC KEY-----\x00",
		"-----BEGIN " + strings.Repeat("A", 1024) + "-----BEGIN CERTIFICATE-----\x00",
		"-----BEGIN " + strings.Repeat("PUBLIC ", 1024),
	} {
		for _, mode := range []Mode{Strict, ReviewedRootLiterals} {
			if _, err := scanChunks(t, mode, []byte(input), 7); err != nil {
				t.Fatal("public BEGIN template treated as private key", err)
			}
		}
	}
	for _, input := range []string{
		"-----BEGIN PUBLIC -----BEGIN PRIVATE KEY-----\x00",
		"-----BEGIN " + strings.Repeat("A", 1024) + "PRIVATE KEY-----\x00",
	} {
		for _, mode := range []Mode{Strict, ReviewedRootLiterals} {
			if _, err := scanChunks(t, mode, []byte(input), 7); !errors.Is(err, ErrPrivateKeyMarker) {
				t.Fatal("eventual private suffix escaped detection", err)
			}
		}
	}
}

func TestFullLiteralBoundAndMutationOutsideLiteral(t *testing.T) {
	literal := []byte("-----BEGIN PRIVATE KEY-----\x00")
	input := append(bytes.Repeat([]byte{'x'}, 128*1024-3), literal...)
	input = append(input, bytes.Repeat([]byte{'z'}, 128*1024)...)
	original := append([]byte{}, input...)
	first, err := scanChunks(t, ReviewedRootLiterals, input, 128*1024)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, original) {
		t.Fatal("scanner mutated caller input")
	}
	input[0] ^= 1
	second, err := scanChunks(t, ReviewedRootLiterals, input, 11)
	if err != nil || second.BytesScanned != first.BytesScanned || second.PublicLiteralMatches[0] != first.PublicLiteralMatches[0] {
		t.Fatal("unrelated mutation changed literal admission")
	}
	atLimit := append([]byte("-----BEGIN PRIVATE KEY-----"), bytes.Repeat([]byte{'x'}, MaxLiteralBytes-1-len("-----BEGIN PRIVATE KEY-----"))...)
	atLimit = append(atLimit, 0)
	if _, err := scanChunks(t, ReviewedRootLiterals, atLimit, 53); !errors.Is(err, ErrPrivateKeyMarker) {
		t.Fatal("unknown literal at maximum length accepted")
	}
}

type noProgressReader struct{}

func (noProgressReader) Read([]byte) (int, error) { return 0, nil }

type failingReader struct{}

func (failingReader) Read(p []byte) (int, error) { copy(p, "prefix"); return 6, io.ErrUnexpectedEOF }

func TestLifecycleAndReaderErrors(t *testing.T) {
	if _, err := New("caller-selected-policy"); err == nil {
		t.Fatal("unknown mode accepted")
	}
	if _, err := Scan(nil, Strict); err == nil {
		t.Fatal("nil reader accepted")
	}
	if _, err := Scan(noProgressReader{}, Strict); !errors.Is(err, io.ErrNoProgress) {
		t.Fatal(err)
	}
	if _, err := Scan(failingReader{}, Strict); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	for _, mode := range []Mode{Strict, ReviewedRootLiterals} {
		report, err := Scan(bytes.NewReader(nil), mode)
		if err != nil || report.Status != "passed" || report.BytesScanned != 0 || report.ProofOfPrivateMaterialAbsence || report.PrivateKeyOperationPerformed {
			t.Fatal("empty scan or negative capabilities failed")
		}
	}
	scanner, _ := New(Strict)
	if _, err := scanner.Finish(); err != nil {
		t.Fatal(err)
	}
	if scanner.Consume(nil) == nil {
		t.Fatal("consume after Finish accepted")
	}
	if _, err := scanner.Finish(); err == nil {
		t.Fatal("second Finish accepted")
	}
	scanner, _ = New(ReviewedRootLiterals)
	if err := scanner.Consume([]byte("-----BEGIN PRIVATE KEY-----")); err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.Finish(); !errors.Is(err, ErrPrivateKeyMarker) {
		t.Fatal("unfinished literal accepted")
	}
	if scanner.Consume([]byte{0}) == nil {
		t.Fatal("failed scan resumed")
	}
	if unsafe.Sizeof(Scanner{}) > 20*1024 {
		t.Fatal("scanner retained state exceeded constant memory bound")
	}
}

func TestBinaryNonProofAndOrdinaryPublicPEM(t *testing.T) {
	for _, input := range [][]byte{{0x30, 0x82, 1, 0x22, 2, 1, 0}, []byte("-----BEGIN PUBLIC KEY-----\npublic\n-----END PUBLIC KEY-----\n"), []byte("-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n")} {
		for _, mode := range []Mode{Strict, ReviewedRootLiterals} {
			report, err := Scan(bytes.NewReader(input), mode)
			if err != nil || report.ProofOfPrivateMaterialAbsence {
				t.Fatal("ordinary public input or non-proof contract failed", err)
			}
		}
	}
}

// This optional source-backed check decodes the already-public GnuTLS C
// constants in memory. Nix/integration checks supply the SHA-pinned source;
// neither the source file nor its PEM bodies are stored in this repository.
func TestReviewedGnuTLSSourceConstants(t *testing.T) {
	path := os.Getenv("KAIBA_PEMMARKERS_PUBLIC_GNUTLS_SOURCE")
	if path == "" {
		t.Skip("source-backed check needs the pinned public GnuTLS source path")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	if hex.EncodeToString(sum[:]) != "6e596be00754107fd7f7d1f132c2dc8cd0ff12bbdfc6de08c162a1dd5eedc7e8" {
		t.Fatal("public GnuTLS source digest mismatch")
	}
	catalog, err := loadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	quoted := regexp.MustCompile(`"(?:\\.|[^"\\])*"`)
	for _, record := range catalog.records {
		if record.Upstream == nil {
			continue
		}
		pattern := regexp.MustCompile(`(?s)const\s+char\s+` + regexp.QuoteMeta(record.Upstream.Constant) + `\[\]\s*=\s*((?:"(?:\\.|[^"\\])*"\s*)+);`)
		match := pattern.FindSubmatch(encoded)
		if len(match) != 2 {
			t.Fatal("public source constant not found", record.ID)
		}
		var literal []byte
		for _, token := range quoted.FindAll(match[1], -1) {
			decoded, err := strconv.Unquote(string(token))
			if err != nil {
				t.Fatal("decode public C string failed")
			}
			literal = append(literal, decoded...)
		}
		literal = append(literal, 0)
		if len(literal) != record.Length || sha256.Sum256(literal) != (func() [32]byte {
			value, _ := hex.DecodeString(record.SHA256)
			var sum [32]byte
			copy(sum[:], value)
			return sum
		})() {
			t.Fatal("source literal does not match reviewed catalog", record.ID)
		}
		for _, chunk := range []int{1, 7, 29, 127, 1024} {
			report, err := scanChunks(t, ReviewedRootLiterals, literal, chunk)
			if err != nil || len(report.PublicLiteralMatches) != 1 || report.PublicLiteralMatches[0].LiteralID != record.ID {
				t.Fatal("public source literal rejected", record.ID, err)
			}
		}
		mutated := append([]byte{}, literal...)
		mutated[len(record.Marker)+2] ^= 1
		if _, err := Scan(bytes.NewReader(mutated), ReviewedRootLiterals); !errors.Is(err, ErrPrivateKeyMarker) {
			t.Fatal("changed public fixture accepted")
		}
		if _, err := Scan(bytes.NewReader(literal[:len(literal)-1]), ReviewedRootLiterals); !errors.Is(err, ErrPrivateKeyMarker) {
			t.Fatal("unterminated public fixture accepted")
		}
		if _, err := Scan(bytes.NewReader(literal), Strict); !errors.Is(err, ErrPrivateKeyMarker) {
			t.Fatal("public fixture accepted in strict metadata mode")
		}
		count++
	}
	if count != 12 {
		t.Fatal("public GnuTLS fixture count mismatch")
	}
}
