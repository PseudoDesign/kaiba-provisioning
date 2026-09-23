package livestation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/guidedcampaign"
)

type campaignSource struct {
	calls int
	err   error
}

func (s *campaignSource) Current(context.Context) (guidedcampaign.Screen, error) {
	return guidedcampaign.Screen{}, s.err
}
func (s *campaignSource) Report(context.Context) (guidedcampaign.Report, error) {
	return guidedcampaign.Report{}, s.err
}
func (s *campaignSource) Apply(context.Context, guidedcampaign.Action) (guidedcampaign.Screen, error) {
	s.calls++
	return guidedcampaign.Screen{}, s.err
}
func TestCampaignKioskRequiresCurrentSameOriginSession(t *testing.T) {
	source := &campaignSource{}
	h, e := NewCampaignHandler(source, "127.0.0.1:8081")
	if e != nil {
		t.Fatal(e)
	}
	runtime := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "http://127.0.0.1:8081/runtime-config.json", nil)
	h.ServeHTTP(runtime, r)
	var config map[string]any
	if json.Unmarshal(runtime.Body.Bytes(), &config) != nil {
		t.Fatal(runtime.Body.String())
	}
	token := config["session_token"].(string)
	if config["schema_version"] != CampaignRuntimeSchema || len(token) != 64 {
		t.Fatal(config)
	}
	request := func(host, origin, session, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://127.0.0.1:8081/api/v1/actions", strings.NewReader(body))
		r.Host = host
		r.Header.Set("Origin", origin)
		r.Header.Set("X-Kaiba-Campaign-Token", session)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	body := `{"request_id":"tap","expected_revision":1,"action":"begin","input":""}`
	for _, v := range [][3]string{{"other.example", "http://127.0.0.1:8081", token}, {"127.0.0.1:8081", "https://evil.example", token}, {"127.0.0.1:8081", "http://127.0.0.1:8081", "old-token"}, {"127.0.0.1:8081", "", token}} {
		if w := request(v[0], v[1], v[2], body); w.Code < 400 {
			t.Fatal(w.Code)
		}
	}
	for _, b := range []string{strings.Replace(body, `"begin"`, `"begin","action":"other"`, 1), strings.Replace(body, `"input":""`, `"input":"","command":"sudo"`, 1), strings.Repeat(" ", 4097)} {
		if w := request("127.0.0.1:8081", "http://127.0.0.1:8081", token, b); w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	if source.calls != 0 {
		t.Fatal("rejected request forwarded")
	}
	if w := request("127.0.0.1:8081", "http://127.0.0.1:8081", token, body); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if source.calls != 1 {
		t.Fatal(source.calls)
	}
	for _, item := range []struct {
		err  error
		code int
	}{{guidedcampaign.ErrDenied, 403}, {guidedcampaign.ErrInvalid, 502}, {guidedcampaign.ErrConflict, 409}, {errors.New("private lower-level failure"), 503}} {
		source.err = item.err
		w := request("127.0.0.1:8081", "http://127.0.0.1:8081", token, body)
		if w.Code != item.code || strings.Contains(w.Body.String(), "private lower-level") {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"/", "/app.js", "/campaign.js", "/styles.css"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1:8081"+path, nil))
		if w.Code != 200 || w.Header().Get("Content-Security-Policy") == "" {
			t.Fatal(path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1:8081/api/v1/report", nil))
	if w.Code != http.StatusForbidden {
		t.Fatal("unauthenticated export", w.Code)
	}
}
