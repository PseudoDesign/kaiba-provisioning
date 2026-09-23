package livestation

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/guidedcampaign"
)

const CampaignRuntimeSchema = "provisioning.kaiba.network/station-campaign-runtime/v1alpha1"

type campaignHandler struct {
	source      guidedcampaign.Source
	host, token string
}

func NewCampaignHandler(source guidedcampaign.Source, host string) (http.Handler, error) {
	if source == nil || ValidateListenAddress(host) != nil {
		return nil, errors.New("campaign source and loopback host required")
	}
	var token [32]byte
	if _, e := rand.Read(token[:]); e != nil {
		return nil, e
	}
	return &campaignHandler{source, host, hex.EncodeToString(token[:])}, nil
}
func (h *campaignHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w.Header())
	if r.Host != h.host {
		writeProblem(w, 421, "invalid_host", "Invalid host", "Use this station's local address.", 0)
		return
	}
	if r.URL.RawQuery != "" || r.URL.RawPath != "" {
		writeProblem(w, 400, "invalid_path", "Invalid path", "Use the fixed station endpoints.", 0)
		return
	}
	switch r.URL.Path {
	case "/":
		serveAsset(w, r, "index.html", "text/html; charset=utf-8")
		return
	case "/app.js":
		serveAsset(w, r, "app.js", "text/javascript; charset=utf-8")
		return
	case "/campaign.js":
		serveAsset(w, r, "campaign.js", "text/javascript; charset=utf-8")
		return
	case "/styles.css":
		serveAsset(w, r, "styles.css", "text/css; charset=utf-8")
		return
	case "/runtime-config.json":
		if r.Method != "GET" {
			methodNotAllowed(w, "GET")
			return
		}
		writeJSON(w, 200, map[string]any{"schema_version": CampaignRuntimeSchema, "state_schema_version": guidedcampaign.StateSchema, "expected_origin": "http://" + h.host, "state_endpoint": "/api/v1/state", "action_endpoint": "/api/v1/actions", "report_endpoint": "/api/v1/report", "session_token": h.token, "refresh_interval_seconds": 2, "production_enrollment": false})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 18*time.Second)
	defer cancel()
	var value any
	var e error
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/v1/state":
		value, e = h.source.Current(ctx)
	case r.Method == "GET" && r.URL.Path == "/api/v1/report":
		if !h.authenticated(r) {
			writeProblem(w, 403, "invalid_session", "Invalid session", "Refresh the station page before exporting.", 0)
			return
		}
		value, e = h.source.Report(ctx)
		if e == nil {
			w.Header().Set("Content-Disposition", `attachment; filename="kaiba-campaign-report.json"`)
		}
	case r.Method == "POST" && r.URL.Path == "/api/v1/actions":
		if !h.authenticated(r) || len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != "http://"+h.host {
			writeProblem(w, 403, "invalid_session", "Invalid session", "Actions require the current station session and same origin.", 0)
			return
		}
		if len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Type") != "application/json" {
			methodNotAllowedJSON(w)
			return
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		var a guidedcampaign.Action
		if err != nil || len(b) > 4096 || guidedcampaign.Decode(b, &a) != nil {
			writeProblem(w, 400, "invalid_action", "Invalid action", "The action input is not supported.", 0)
			return
		}
		value, e = h.source.Apply(ctx, a)
	default:
		writeProblem(w, 404, "not_found", "Not found", "The resource does not exist.", 0)
		return
	}
	if e != nil {
		code := 503
		reason := "unavailable"
		detail := "Reconnect to the campaign authority before continuing."
		switch {
		case errors.Is(e, guidedcampaign.ErrConflict):
			code = 409
			reason = "state_changed"
			detail = "The action may already be recorded. Refresh before continuing."
		case errors.Is(e, guidedcampaign.ErrDenied):
			code = 403
			reason = "denied"
			detail = "The station cannot access this campaign."
		case errors.Is(e, guidedcampaign.ErrInput):
			code = 400
			reason = "invalid_action"
			detail = "The action input is not supported."
		case errors.Is(e, guidedcampaign.ErrInvalid):
			code = 502
			reason = "invalid_state"
			detail = "The campaign response was invalid. Have the station configuration reviewed."
		}
		writeProblem(w, code, reason, "Campaign unavailable", detail, 0)
		return
	}
	writeJSON(w, 200, value)
}
func (h *campaignHandler) authenticated(r *http.Request) bool {
	return len(r.Header.Values("X-Kaiba-Campaign-Token")) == 1 && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Kaiba-Campaign-Token")), []byte(h.token)) == 1
}
func methodNotAllowedJSON(w http.ResponseWriter) {
	writeProblem(w, 415, "invalid_content_type", "Invalid content type", "Use application/json with no parameters.", 0)
}
func ListenAndServeCampaign(ctx context.Context, address string, source guidedcampaign.Source) error {
	return listenAndServe(ctx, address, func(host string) (http.Handler, error) { return NewCampaignHandler(source, host) }, 20*time.Second)
}
