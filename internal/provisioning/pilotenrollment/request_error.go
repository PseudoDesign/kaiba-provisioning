package pilotenrollment

import "fmt"

// RequestError contains only bounded classifications, never response bodies,
// URLs, certificate contents or underlying transport error text.
// A failed request does not establish whether the authority committed a write.
type RequestError struct {
	Kind       string `json:"error"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

func (e *RequestError) Error() string {
	if e.HTTPStatus != 0 {
		return fmt.Sprintf("pilot request %s (HTTP %d); no automatic retry", e.Kind, e.HTTPStatus)
	}
	return "pilot request " + e.Kind + "; no automatic retry"
}
func (e *RequestError) Unwrap() error { return ErrReconcile }
