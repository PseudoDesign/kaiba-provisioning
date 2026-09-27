//go:build linux

package pilotenrollment

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestIsolationExplicitDenialAndUnchangedState(t *testing.T) {
	calls := []string{}
	c, _, dir := readTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || len(r.TLS.VerifiedChains) == 0 {
			t.Error("expected authenticated GET")
		}
		calls = append(calls, r.URL.Path)
		if r.URL.Path == "/api/v1/pilot/self" {
			fmt.Fprint(w, `{"authorized":"pilot","instance_id":"instance","binding":{},"full_qualification":false}`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})
	before, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	result, err := c.CheckIsolation(context.Background(), "other")
	if err != nil || result.Other != "other" || result.HTTPStatus != 403 || result.Schema != "kaiba.pilot-isolation/v1alpha1" {
		t.Fatalf("isolation: %+v %v", result, err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if string(before) != string(after) || !reflect.DeepEqual(calls, []string{"/api/v1/pilot/self", "/api/v1/pilot/enrollments/other"}) {
		t.Fatal("unexpected writes, request path or replay")
	}
	for _, id := range []string{"", "instance", "../self", "other?x=1", "other/activate", "https://other"} {
		if _, err = c.CheckIsolation(context.Background(), id); err == nil {
			t.Fatalf("accepted %q", id)
		}
	}
	if len(calls) != 2 {
		t.Fatal("invalid identifier sent to authority")
	}
}

func TestIsolationFailureIsNotDenial(t *testing.T) {
	for _, status := range []int{200, 401, 404, 409, 500, 503, 302} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			c, _, _ := readTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path == "/api/v1/pilot/self" {
					fmt.Fprint(w, `{"authorized":"pilot","instance_id":"instance","binding":{},"full_qualification":false}`)
					return
				}
				w.WriteHeader(status)
				fmt.Fprint(w, `{}`)
			})
			if _, err := c.CheckIsolation(context.Background(), "other"); err == nil {
				t.Fatal("non-denial accepted")
			}
			if calls != 2 {
				t.Fatal("unexpected retry")
			}
		})
	}
	t.Run("self denied", func(t *testing.T) {
		calls := 0
		c, _, _ := readTestClient(t, func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(403) })
		if _, err := c.CheckIsolation(context.Background(), "other"); err == nil || calls != 1 {
			t.Fatal("failed own access counted as isolation")
		}
	})
	t.Run("unavailable", func(t *testing.T) {
		c, s, _ := readTestClient(t, func(http.ResponseWriter, *http.Request) {})
		s.Close()
		if _, err := c.CheckIsolation(context.Background(), "other"); err == nil {
			t.Fatal("outage accepted")
		}
	})
}
