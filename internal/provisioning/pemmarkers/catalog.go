package pemmarkers

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"
)

// The catalog contains hashes and public provenance, never PEM bodies. It is
// compiled into the scanner; there is no caller-selected exception catalog.
//
//go:embed reviewed_literals.json
var catalogBytes []byte

type publicFileProof struct {
	Path    string  `json:"path"`
	SHA256  string  `json:"file_sha256"`
	Size    int64   `json:"file_size_bytes"`
	Format  string  `json:"format"`
	Offsets []int64 `json:"literal_offsets"`
}
type upstreamSourceProof struct {
	Archive         string `json:"archive"`
	ArchiveSHA256   string `json:"archive_sha256"`
	Member          string `json:"member"`
	MemberSHA256    string `json:"member_sha256"`
	Constant        string `json:"constant"`
	DeclarationLine int    `json:"declaration_line"`
	UseLines        []int  `json:"selftest_use_lines"`
}
type literalRecord struct {
	ID             string               `json:"id"`
	MarkerType     string               `json:"marker_type"`
	Marker         string               `json:"marker"`
	Length         int                  `json:"length_including_nul"`
	SHA256         string               `json:"sha256_including_nul"`
	Classification string               `json:"classification"`
	PublicFiles    []publicFileProof    `json:"public_file_proofs"`
	Upstream       *upstreamSourceProof `json:"upstream_source_proof"`
}
type catalogKey struct {
	marker string
	length int
	digest [32]byte
}
type literalCatalog struct {
	records   []literalRecord
	byLiteral map[catalogKey]int
	digest    string
}

var catalogOnce sync.Once
var compiledCatalog literalCatalog
var catalogError error

func loadCatalog() (*literalCatalog, error) {
	catalogOnce.Do(func() { compiledCatalog, catalogError = parseCatalog(catalogBytes) })
	return &compiledCatalog, catalogError
}

func parseCatalog(encoded []byte) (literalCatalog, error) {
	var document struct {
		SchemaVersion    string          `json:"schema_version"`
		DigestDefinition string          `json:"digest_definition"`
		Records          []literalRecord `json:"records"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return literalCatalog{}, err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || document.SchemaVersion != "kaiba.public-root-pem-literals/v1alpha1" || len(document.Records) != 21 {
		return literalCatalog{}, errors.New("invalid compiled public literal catalog")
	}
	catalog := literalCatalog{records: document.Records, byLiteral: make(map[catalogKey]int)}
	ids := map[string]bool{}
	for i, record := range catalog.records {
		digest, err := hex.DecodeString(record.SHA256)
		if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != record.SHA256 || record.ID != "public-literal-"+record.SHA256[:16] || ids[record.ID] || record.Length <= len(record.Marker) || record.Length > MaxLiteralBytes || markerTypes[record.Marker] != record.MarkerType || record.MarkerType == "" || len(record.PublicFiles) == 0 {
			return literalCatalog{}, errors.New("invalid compiled public literal record")
		}
		ids[record.ID] = true
		var sum [32]byte
		copy(sum[:], digest)
		key := catalogKey{record.Marker, record.Length, sum}
		if _, exists := catalog.byLiteral[key]; exists {
			return literalCatalog{}, errors.New("duplicate compiled public literal record")
		}
		catalog.byLiteral[key] = i
	}
	digest := sha256.Sum256(encoded)
	catalog.digest = "sha256:" + hex.EncodeToString(digest[:])
	return catalog, nil
}
