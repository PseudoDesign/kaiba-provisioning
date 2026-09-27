//go:build linux

package pilotenrollment

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
)

var enrollmentPathID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// IsolationResult records authenticated own access followed by an explicit
// denial for one other enrollment. It contains no private credential material.
type IsolationResult struct {
	Schema     string          `json:"schema_version"`
	Self       json.RawMessage `json:"self"`
	Other      string          `json:"other_instance_id"`
	HTTPStatus int             `json:"http_status"`
}

// CheckIsolation uses the currently selected credential, including after
// recovery/renewal. Both requests are GETs; it neither changes state nor retries.
// The caller must independently verify that other is an existing enrollment.
func (c *Client) CheckIsolation(ctx context.Context, other string) (IsolationResult, error) {
	if c.value.Bootstrap == nil || !enrollmentPathID.MatchString(other) || other == c.value.Bootstrap.Enrollment {
		return IsolationResult{}, ErrBinding
	}
	self, err := c.CheckAccess(ctx)
	if err != nil {
		return IsolationResult{}, err
	}
	_, err = c.request(ctx, http.MethodGet, "/api/v1/pilot/enrollments/"+other, nil)
	var rejected *RequestError
	if errors.As(err, &rejected) && rejected.Kind == "http_status" && rejected.HTTPStatus == http.StatusForbidden {
		return IsolationResult{"kaiba.pilot-isolation/v1alpha1", self, other, http.StatusForbidden}, nil
	}
	if err != nil {
		return IsolationResult{}, err
	}
	return IsolationResult{}, errors.New("isolation_not_enforced")
}
