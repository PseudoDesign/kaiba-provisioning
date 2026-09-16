package livestation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type observationSourceFunc func(context.Context) (ObservationState, error)

func (source observationSourceFunc) Current(ctx context.Context) (ObservationState, error) {
	return source(ctx)
}

func TestObservationHandlerReadOnlySurface(t *testing.T) {
	f := newObservationFixture(t)
	f.claim()
	observer, err := NewObserver(observerConfig(t), f.service)
	if err != nil {
		t.Fatal(err)
	}
	reads := 0
	handler, err := NewObserverHandler(observationSourceFunc(func(ctx context.Context) (ObservationState, error) {
		reads++
		return observer.Current(ctx)
	}), testHost)
	if err != nil {
		t.Fatal(err)
	}
	response := doRequest(handler, http.MethodGet, "/runtime-config.json", "", "", "")
	var runtime ObservationRuntime
	if err := json.Unmarshal(response.Body.Bytes(), &runtime); err != nil {
		t.Fatal(err)
	}
	if response.Code != 200 || runtime.SchemaVersion != ObservationRuntimeSchemaVersion || runtime.StateSchemaVersion != ObservationStateSchemaVersion || runtime.ExpectedOrigin != "http://"+testHost || runtime.StateEndpoint != "/api/v1/state" || !runtime.ReadOnly || runtime.Simulation || runtime.EnrollmentCapable || runtime.RefreshIntervalSeconds != 5 || strings.Contains(response.Body.String(), "action_endpoint") {
		t.Fatalf("runtime = %s", response.Body.String())
	}
	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodHead, http.MethodOptions} {
		response = doRequest(handler, method, "/api/v1/actions", `{"action":"execute_commit"}`, "", "")
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"type":"read_only"`) {
			t.Fatalf("action %s = %d %s", method, response.Code, response.Body.String())
		}
	}
	for _, test := range []struct {
		method, path string
		status       int
	}{
		{http.MethodGet, "/", 200}, {http.MethodGet, "/app.js", 200}, {http.MethodGet, "/styles.css", 200},
		{http.MethodHead, "/", 405}, {http.MethodPost, "/api/v1/state", 405},
		{http.MethodPost, "/runtime-config.json", 405}, {http.MethodGet, "/api/v1/state?debug=1", 400},
		{http.MethodGet, "/index.html", 404}, {http.MethodGet, "/api/v1/transactions", 404},
	} {
		response = doRequest(handler, test.method, test.path, "", "", "")
		if response.Code != test.status || response.Header().Get("Cache-Control") != "no-store" || !strings.Contains(response.Header().Get("Content-Security-Policy"), "connect-src 'self'") || response.Header().Get("X-Frame-Options") != "DENY" {
			t.Fatalf("%s %s = %d", test.method, test.path, response.Code)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "http://evil.example/api/v1/state", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusMisdirectedRequest || reads != 0 {
		t.Fatal("invalid request reached authority")
	}
	response = doRequest(handler, http.MethodGet, "/api/v1/state", "", "", "")
	var state ObservationState
	if err := json.Unmarshal(response.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if response.Code != 200 || state.SchemaVersion != ObservationStateSchemaVersion || state.ReadStatus != "current" || reads != 1 {
		t.Fatalf("state = %s", response.Body.String())
	}
}

func TestObservationHandlerConfigurationAndSourceFailure(t *testing.T) {
	if _, err := NewObserverHandler(nil, testHost); err == nil {
		t.Fatal("nil source accepted")
	}
	source := observationSourceFunc(func(context.Context) (ObservationState, error) {
		return ObservationState{}, errors.New("secret transport detail")
	})
	if _, err := NewObserverHandler(source, "0.0.0.0:8081"); err == nil {
		t.Fatal("non-loopback accepted")
	}
	handler, err := NewObserverHandler(source, testHost)
	if err != nil {
		t.Fatal(err)
	}
	response := doRequest(handler, http.MethodGet, "/api/v1/state", "", "", "")
	if response.Code != 503 || strings.Contains(response.Body.String(), "secret transport detail") {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
}
