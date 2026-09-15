package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestValidAndAlteredPlan(t *testing.T) {
	data, err := os.ReadFile("../../internal/provisioning/campaignmedia/testdata/recovery-v1alpha2/staging-plan.json")
	if err != nil {
		t.Fatal(err)
	}
	var output, diagnostics bytes.Buffer
	if status := run(nil, bytes.NewReader(data), &output, &diagnostics); status != 0 {
		t.Fatalf("valid plan status %d: %s", status, &diagnostics)
	}
	var report map[string]any
	if err := json.Unmarshal(output.Bytes(), &report); err != nil || report["status"] != "valid" || report["destructive_staging_ready"] != false {
		t.Fatalf("unexpected report: %s", &output)
	}
	for name, changed := range map[string][]byte{
		"changed SD identity":    bytes.Replace(data, []byte("5625eee2-0c8a-402f-8c2f-5a1347652bb2"), []byte("6625eee2-0c8a-402f-8c2f-5a1347652bb2"), 1),
		"invalid final GPT hash": bytes.Replace(data, []byte("sha256:"), []byte("sha255:"), 1),
		"unknown field":          bytes.Replace(data, []byte("{\"schema_version\""), []byte("{\"unknown\":false,\"schema_version\""), 1),
		"trailing JSON":          append(append([]byte{}, data...), []byte("{}")...),
	} {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(changed, data) {
				t.Fatal("fixture mutation did not change input")
			}
			output.Reset()
			diagnostics.Reset()
			if status := run(nil, bytes.NewReader(changed), &output, &diagnostics); status != 1 || output.Len() != 0 {
				t.Fatalf("altered input accepted: status=%d output=%q", status, &output)
			}
		})
	}
}

func TestBoundsAndNoPathArguments(t *testing.T) {
	for _, input := range []string{"", strings.Repeat("x", maximumPlanBytes+1)} {
		var output, diagnostics bytes.Buffer
		if run(nil, strings.NewReader(input), &output, &diagnostics) != 1 || output.Len() != 0 {
			t.Fatal("invalid input accepted")
		}
	}
	var output, diagnostics bytes.Buffer
	if run([]string{"/dev/anything"}, strings.NewReader(""), &output, &diagnostics) != 2 {
		t.Fatal("path argument accepted")
	}
}
