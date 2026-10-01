//go:build linux

package pilotenrollment

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInspectTrustIsLocalAndPreservesProtectedState(t *testing.T) {
	c, _, dir, ca, _ := readTestClientIssuer(t, func(http.ResponseWriter, *http.Request) { t.Error("unexpected network access") })
	defer c.Close()
	renewalFixture(t, c)
	c.runtime.ClockCertain = func() bool { return true }
	now := time.Now()
	c.runtime.Now = func() time.Time { return now }
	statePath := filepath.Join(dir, "state.json")
	before, e := os.ReadFile(statePath)
	if e != nil {
		t.Fatal(e)
	}
	stored := append([]byte(nil), canon(c.value)...)
	observation, e := c.InspectTrust()
	if e != nil {
		t.Fatal(e)
	}
	status, _ := c.Status()
	if observation.Enrollment != status.Enrollment || observation.Logical != status.Logical || observation.SPKI != status.SPKIDigest || observation.Server.After != ca.NotAfter.UTC().Format(time.RFC3339Nano) {
		t.Fatal("wrong scope or selected certificate")
	}
	raw := string(canon(observation))
	for _, forbidden := range []string{"PRIVATE KEY", "BEGIN CERTIFICATE", "server_ca_pem", "issuer_ca_pem", "private_key"} {
		if strings.Contains(raw, forbidden) {
			t.Fatal("credential content exported")
		}
	}
	storage := c.runtime.CheckStorage
	for _, tc := range []struct {
		name                      string
		uncertain, storageFailure bool
		step                      time.Duration
	}{
		{"uncertain time", true, false, 0},
		{"mount lost", false, true, 0},
		{"clock rollback", false, false, -time.Second},
		{"slow observation", false, false, 16 * time.Second},
		{"certificate expires during observation", false, false, time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := now
			if tc.name == "certificate expires during observation" {
				start = ca.NotAfter.Add(-time.Second)
			}
			calls := 0
			c.runtime.Now = func() time.Time {
				calls++
				if calls > 1 {
					return start.Add(tc.step)
				}
				return start
			}
			c.runtime.ClockCertain = func() bool { return !tc.uncertain }
			c.runtime.CheckStorage = storage
			if tc.storageFailure {
				c.runtime.CheckStorage = func(*os.File, string) error { return errors.New("storage unavailable") }
			}
			if _, e := c.InspectTrust(); e == nil {
				t.Fatal("unsafe observation accepted")
			}
		})
	}
	after, e := os.ReadFile(statePath)
	if e != nil || !bytes.Equal(before, after) || !bytes.Equal(stored, canon(c.value)) {
		t.Fatal("observation mutated state", e)
	}
}
