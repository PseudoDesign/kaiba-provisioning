// Package pemmarkers supplies a bounded, streaming defense-in-depth PEM marker
// scan. A passing scan is not proof that input bytes contain no private material.
// Only the reviewed-root-literals mode permits exact, source-reviewed public
// NUL-terminated constants; metadata and other roles retain strict rejection.
package pemmarkers

import (
	"crypto/sha256"
	"errors"
	"io"
)

type Mode string

const (
	Strict               Mode = "strict"
	ReviewedRootLiterals Mode = "reviewed-root-literals"
	MaxLiteralBytes           = 16 * 1024
	maxHeaderBytes            = 128
	readChunkBytes            = 128 * 1024
	markerPrefix              = "-----BEGIN "
	markerSuffix              = "PRIVATE KEY-----"
)

var ErrPrivateKeyMarker = errors.New("unrecognized private-key PEM marker (scoped defense in depth; not proof of private-material absence)")
var markerTypes = map[string]string{
	"-----BEGIN PRIVATE KEY-----":           "private_key",
	"-----BEGIN ENCRYPTED PRIVATE KEY-----": "encrypted_private_key",
	"-----BEGIN RSA PRIVATE KEY-----":       "rsa_private_key",
	"-----BEGIN EC PRIVATE KEY-----":        "ec_private_key",
	"-----BEGIN DSA PRIVATE KEY-----":       "dsa_private_key",
	"-----BEGIN OPENSSH PRIVATE KEY-----":   "openssh_private_key",
}

type Match struct {
	LiteralID   string `json:"literal_id"`
	Occurrences uint64 `json:"occurrences"`
}
type Report struct {
	Status                        string  `json:"status"`
	Mode                          Mode    `json:"mode"`
	BytesScanned                  uint64  `json:"bytes_scanned"`
	PublicLiteralMatches          []Match `json:"public_literal_matches"`
	CatalogDigest                 string  `json:"catalog_digest"`
	ProofOfPrivateMaterialAbsence bool    `json:"proof_of_private_material_absence"`
	PrivateKeyOperationPerformed  bool    `json:"private_key_operation_performed"`
}

// Scanner retains at most one 16-KiB candidate literal and a 128-byte header,
// irrespective of total input size or the size of a Consume call. Finish is
// mandatory: it rejects a recognized marker lacking its terminating NUL.
type Scanner struct {
	mode           Mode
	catalog        *literalCatalog
	header         [maxHeaderBytes]byte
	headerLength   int
	headerOverflow bool
	suffixMatched  int
	literal        [MaxLiteralBytes]byte
	literalLength  int
	literalMarker  string
	prefixMatched  int
	bytesScanned   uint64
	counts         [21]uint64
	failure        error
	finished       bool
}

func New(mode Mode) (*Scanner, error) {
	if mode != Strict && mode != ReviewedRootLiterals {
		return nil, errors.New("unsupported PEM marker scan mode")
	}
	catalog, err := loadCatalog()
	if err != nil {
		return nil, err
	}
	return &Scanner{mode: mode, catalog: catalog}, nil
}

func (scanner *Scanner) fail(err error) error { scanner.failure = err; return err }

// Consume never modifies input and never retains references to caller buffers.
func (scanner *Scanner) Consume(chunk []byte) error {
	if scanner.failure != nil {
		return scanner.failure
	}
	if scanner.finished {
		return errors.New("PEM marker scanner is already finished")
	}
	if uint64(len(chunk)) > ^uint64(0)-scanner.bytesScanned {
		return scanner.fail(errors.New("PEM scan byte counter overflow"))
	}
	for _, value := range chunk {
		scanner.bytesScanned++
		if scanner.literalLength > 0 {
			if scanner.literalLength == MaxLiteralBytes {
				return scanner.fail(ErrPrivateKeyMarker)
			}
			scanner.literal[scanner.literalLength] = value
			scanner.literalLength++
			if value == 0 {
				key := catalogKey{scanner.literalMarker, scanner.literalLength, sha256.Sum256(scanner.literal[:scanner.literalLength])}
				index, known := scanner.catalog.byLiteral[key]
				if !known {
					return scanner.fail(ErrPrivateKeyMarker)
				}
				scanner.counts[index]++
				scanner.literalLength = 0
				scanner.literalMarker = ""
			}
		}
		if scanner.headerLength > 0 {
			if !headerByte(value) {
				scanner.headerLength = 0
				scanner.headerOverflow = false
				scanner.suffixMatched = 0
			} else {
				// A long or repeated public BEGIN template is not itself a
				// private-key marker. Preserve bounded candidate/suffix state
				// until the actual PRIVATE KEY suffix appears or the label ends.
				if scanner.headerLength == maxHeaderBytes {
					scanner.headerOverflow = true
				} else {
					scanner.header[scanner.headerLength] = value
					scanner.headerLength++
				}
				if value == markerSuffix[scanner.suffixMatched] {
					scanner.suffixMatched++
				} else if value == markerSuffix[0] {
					scanner.suffixMatched = 1
				} else {
					scanner.suffixMatched = 0
				}
				if scanner.suffixMatched == len(markerSuffix) {
					if scanner.mode == Strict || scanner.literalLength > 0 || scanner.headerOverflow {
						return scanner.fail(ErrPrivateKeyMarker)
					}
					marker := string(scanner.header[:scanner.headerLength])
					if markerTypes[marker] == "" {
						return scanner.fail(ErrPrivateKeyMarker)
					}
					copy(scanner.literal[:], scanner.header[:scanner.headerLength])
					scanner.literalLength = scanner.headerLength
					scanner.literalMarker = marker
					scanner.headerLength = 0
					scanner.suffixMatched = 0
				}
			}
		}
		// A tiny prefix automaton handles repeated '-' and marker prefixes
		// split anywhere across chunks, without allocating per input byte.
		for scanner.prefixMatched > 0 && value != markerPrefix[scanner.prefixMatched] {
			scanner.prefixMatched = prefixFallback[scanner.prefixMatched-1]
		}
		if value == markerPrefix[scanner.prefixMatched] {
			scanner.prefixMatched++
		}
		if scanner.prefixMatched == len(markerPrefix) {
			if scanner.headerLength == 0 {
				copy(scanner.header[:], markerPrefix)
				scanner.headerLength = len(markerPrefix)
				scanner.headerOverflow = false
				scanner.suffixMatched = 0
			}
			scanner.prefixMatched = prefixFallback[len(markerPrefix)-1]
		}
	}
	return nil
}

func headerByte(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == ' ' || value == '-'
}

var prefixFallback = func() [len(markerPrefix)]int {
	var table [len(markerPrefix)]int
	for i, j := 1, 0; i < len(markerPrefix); i++ {
		for j > 0 && markerPrefix[i] != markerPrefix[j] {
			j = table[j-1]
		}
		if markerPrefix[i] == markerPrefix[j] {
			j++
		}
		table[i] = j
	}
	return table
}()

func (scanner *Scanner) Finish() (Report, error) {
	if scanner.failure != nil {
		return Report{}, scanner.failure
	}
	if scanner.finished {
		return Report{}, errors.New("PEM marker scanner is already finished")
	}
	scanner.finished = true
	if scanner.literalLength > 0 {
		return Report{}, scanner.fail(ErrPrivateKeyMarker)
	}
	report := Report{Status: "passed", Mode: scanner.mode, BytesScanned: scanner.bytesScanned, PublicLiteralMatches: []Match{}, CatalogDigest: scanner.catalog.digest}
	for index, count := range scanner.counts {
		if count > 0 {
			report.PublicLiteralMatches = append(report.PublicLiteralMatches, Match{scanner.catalog.records[index].ID, count})
		}
	}
	return report, nil
}

// Scan reads sequentially in bounded chunks and propagates all read failures.
func Scan(reader io.Reader, mode Mode) (Report, error) {
	scanner, err := New(mode)
	if err != nil {
		return Report{}, err
	}
	if reader == nil {
		return Report{}, errors.New("PEM scan requires a reader")
	}
	buffer := make([]byte, readChunkBytes)
	emptyReads := 0
	for {
		n, readErr := reader.Read(buffer)
		if n < 0 || n > len(buffer) {
			return Report{}, errors.New("invalid PEM scan reader count")
		}
		if n > 0 {
			emptyReads = 0
			if err := scanner.Consume(buffer[:n]); err != nil {
				return Report{}, err
			}
		} else {
			emptyReads++
		}
		if readErr == io.EOF {
			return scanner.Finish()
		}
		if readErr != nil {
			return Report{}, readErr
		}
		if emptyReads >= 100 {
			return Report{}, io.ErrNoProgress
		}
	}
}
