package guidedcampaign

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mtls"
)

type Source interface {
	Current(context.Context) (Screen, error)
	Apply(context.Context, Action) (Screen, error)
	Report(context.Context) (Report, error)
}

func Handler(e *Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		identity, err := mtls.MutualTLSIdentityPolicy().Authenticate(r)
		if err != nil || identity.StationID != e.plan.Station || identity.LaneID != e.plan.Lane {
			reply(w, 403, map[string]string{"error": "scope_denied"})
			return
		}
		if r.URL.RawQuery != "" || r.URL.RawPath != "" {
			reply(w, 400, map[string]string{"error": "invalid_path"})
			return
		}
		var value any
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/v1/campaign/state":
			value, err = e.Current(r.Context())
		case r.Method == "GET" && r.URL.Path == "/api/v1/campaign/report":
			value, err = e.Report(r.Context())
		case r.Method == "POST" && r.URL.Path == "/api/v1/campaign/actions":
			if len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Type") != "application/json" {
				reply(w, 415, map[string]string{"error": "invalid_content_type"})
				return
			}
			b, x := io.ReadAll(io.LimitReader(r.Body, 4097))
			var a Action
			if x != nil || len(b) > 4096 || Decode(b, &a) != nil {
				reply(w, 400, map[string]string{"error": "invalid_action"})
				return
			}
			value, err = e.Apply(r.Context(), a)
		default:
			reply(w, 404, map[string]string{"error": "not_found"})
			return
		}
		if err != nil {
			status := 503
			if errors.Is(err, ErrConflict) {
				status = 409
			}
			if errors.Is(err, ErrInput) {
				status = 400
			}
			reply(w, status, map[string]string{"error": "campaign_request_failed"})
			return
		}
		reply(w, 200, value)
	})
}
func reply(w http.ResponseWriter, code int, v any) { w.WriteHeader(code); _, _ = w.Write(encoded(v)) }

type Client struct {
	base, id, plan string
	http           *http.Client
}

func NewClient(base, id, plan, station, lane string, files mtls.ClientFiles) (*Client, error) {
	u, e := url.Parse(base)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.ForceQuery || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") || !idPattern.MatchString(id) || !digestPattern.MatchString(plan) {
		return nil, ErrInput
	}
	c, e := mtls.LoadClientConfig(files)
	if e != nil {
		return nil, e
	}
	leaf, e := x509.ParseCertificate(c.Certificates[0].Certificate[0])
	if e != nil {
		return nil, e
	}
	identity, e := mtls.ParseStationLaneCertificate(leaf)
	if e != nil || identity.StationID != station || identity.LaneID != lane {
		return nil, mtls.ErrClientIdentityMismatch
	}
	tr := &http.Transport{TLSClientConfig: c, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	return &Client{strings.TrimSuffix(base, "/"), id, plan, &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalid }}}, nil
}
func (c *Client) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		body = strings.NewReader(string(encoded(in)))
	}
	r, e := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if e != nil {
		return ErrInput
	}
	if in != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	res, e := c.http.Do(r)
	if e != nil {
		if errors.Is(e, ErrInvalid) {
			return ErrInvalid
		}
		return ErrUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode == 401 || res.StatusCode == 403 || res.StatusCode == 404 {
		return ErrDenied
	}
	if res.StatusCode == 409 {
		return ErrConflict
	}
	if res.StatusCode >= 500 {
		return ErrUnavailable
	}
	if res.StatusCode != 200 {
		return ErrInvalid
	}
	if strings.ToLower(strings.TrimSpace(strings.Split(res.Header.Get("Content-Type"), ";")[0])) != "application/json" {
		return ErrInvalid
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, MaxBytes+1))
	if e != nil || Decode(b, out) != nil {
		return ErrInvalid
	}
	return nil
}
func (c *Client) check(s Screen) error {
	if s.Schema != StateSchema || s.Campaign != c.id || s.Plan != c.plan || s.Production || s.Qualified || s.Revision == 0 || s.Revision > 9007199254740991 || s.Total < 1 || s.Total > 32 || s.Number < 1 || s.Number > s.Total || s.Actions == nil || (s.Mode != "development" && s.Mode != "software_rehearsal") {
		return ErrInvalid
	}
	return nil
}
func (c *Client) Current(ctx context.Context) (Screen, error) {
	var s Screen
	e := c.call(ctx, "GET", "/api/v1/campaign/state", nil, &s)
	if e == nil {
		e = c.check(s)
	}
	return s, e
}
func (c *Client) Apply(ctx context.Context, a Action) (Screen, error) {
	var s Screen
	e := c.call(ctx, "POST", "/api/v1/campaign/actions", a, &s)
	if e == nil {
		e = c.check(s)
	}
	return s, e
}
func (c *Client) Report(ctx context.Context) (Report, error) {
	var r Report
	e := c.call(ctx, "GET", "/api/v1/campaign/report", nil, &r)
	if e == nil && (r.Schema != ReportSchema || c.check(r.State) != nil || r.EvidenceBasis != "packet_executor_records_not_independent_audit" || len(r.Conditions) != 8) {
		e = ErrInvalid
	}
	return r, e
}

// TLSConfig keeps service configuration validation outside the kiosk process.
func TLSConfig(files mtls.Files) (*tls.Config, error) { return mtls.LoadServerConfig(files) }
