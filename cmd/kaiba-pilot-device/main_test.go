package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/pilotenrollment"
	"strings"
	"testing"
)

func TestBoundedRequestErrorOutput(t *testing.T) {
	var b bytes.Buffer
	err := errors.Join(errors.New("sensitive nested text"), &pilotenrollment.RequestError{Kind: "http_status", HTTPStatus: 403})
	if !writeRequestError(&b, err) {
		t.Fatal("not classified")
	}
	var value map[string]any
	if json.Unmarshal(b.Bytes(), &value) != nil || value["http_status"] != float64(403) || value["error"] != "http_status" || value["reconciliation_required"] != true || value["schema_version"] != "kaiba.pilot-device-error/v1alpha1" || strings.Contains(b.String(), "sensitive") {
		t.Fatalf("unsafe output: %s", b.String())
	}
	b.Reset()
	if writeRequestError(&b, pilotenrollment.ErrInput) || b.Len() != 0 {
		t.Fatal("unexpected output")
	}
}
