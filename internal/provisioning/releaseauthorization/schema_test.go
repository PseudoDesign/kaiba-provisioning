package releaseauthorization

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestWireErrorDocumentsMatchPublishedSchema(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	schemaPath := ""
	for directory := workingDirectory; ; directory = filepath.Dir(directory) {
		candidate := filepath.Join(directory, "schemas/rpi5-boot-authorization-v1alpha1.schema.json")
		if info, statErr := os.Stat(candidate); statErr == nil && info.Mode().IsRegular() {
			schemaPath = candidate
			break
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			break
		}
	}
	if schemaPath == "" {
		t.Fatal("could not locate rpi5 boot-authorization schema from the test working directory")
	}
	encodedSchema, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Definitions map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(encodedSchema, &schema); err != nil {
		t.Fatal(err)
	}
	var errorDefinition struct {
		AdditionalProperties bool                       `json:"additionalProperties"`
		Required             []string                   `json:"required"`
		Properties           map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(schema.Definitions["error"], &errorDefinition); err != nil {
		t.Fatalf("decode $defs.error: %v", err)
	}
	if errorDefinition.AdditionalProperties || !reflect.DeepEqual(errorDefinition.Required, []string{"schema_version", "code"}) {
		t.Fatalf("error definition has unsafe shape: %#v", errorDefinition)
	}
	var versionProperty struct {
		Const string `json:"const"`
	}
	if err := json.Unmarshal(errorDefinition.Properties["schema_version"], &versionProperty); err != nil {
		t.Fatal(err)
	}
	if versionProperty.Const != ErrorSchemaVersion {
		t.Fatalf("schema error version = %q, wire version = %q", versionProperty.Const, ErrorSchemaVersion)
	}
	var codeProperty struct {
		Enum []string `json:"enum"`
	}
	if err := json.Unmarshal(errorDefinition.Properties["code"], &codeProperty); err != nil {
		t.Fatal(err)
	}
	wireCodes := []string{
		"authorization_unknown", "binding_mismatch", "binding_unauthorized", "bootstrap_untrusted",
		"challenge_capacity", "challenge_expired", "challenge_replayed", "challenge_unknown",
		"internal_error", "invalid_request", "one_boot_proof_replayed", "request_too_large", "signature_invalid",
	}
	sort.Strings(codeProperty.Enum)
	sort.Strings(wireCodes)
	if !reflect.DeepEqual(codeProperty.Enum, wireCodes) {
		t.Fatalf("schema error codes = %q, wire codes = %q", codeProperty.Enum, wireCodes)
	}
	for _, code := range wireCodes {
		encoded, err := (errorResponse{SchemaVersion: ErrorSchemaVersion, Code: code}).canonicalJSON()
		if err != nil {
			t.Fatalf("canonical %s error: %v", code, err)
		}
		remote, err := parseErrorResponse(encoded, statusForRemoteCode(code))
		if err != nil || remote.Code != code {
			t.Fatalf("parse %s error = %#v, %v", code, remote, err)
		}
	}
}
