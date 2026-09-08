package releaseauthorization

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
)

const (
	ChallengeEndpoint             = "/non-production/v1alpha1/challenges"
	AuthorizationEndpoint         = "/non-production/v1alpha1/authorizations"
	OneBootProofEndpoint          = "/non-production/v1alpha1/one-boot-proofs"
	BootstrapRegistrationEndpoint = "/non-production/v1alpha1/bootstrap-registrations"
	ErrorSchemaVersion            = "kaiba.provisioning.rpi5-non-production-boot-authorization-error/v1alpha1"
)

type errorResponse struct {
	SchemaVersion string `json:"schema_version"`
	Code          string `json:"code"`
}

type unixAdminContextKey struct{}

// RemoteError is a schema-validated error returned by the test authority. Its
// Unwrap mapping lets callers retry only an explicitly expected condition such
// as ErrUntrustedBootstrap while treating every other result as fail-closed.
type RemoteError struct {
	StatusCode int
	Code       string
}

func (remote *RemoteError) Error() string {
	return fmt.Sprintf("non-production authorization server returned HTTP %d (%s)", remote.StatusCode, remote.Code)
}

func (remote *RemoteError) Unwrap() error {
	return sentinelForRemoteCode(remote.Code)
}

// NonProductionHandler exposes the bounded test-authority HTTP surface. Every
// request requires an established TLS 1.3 session. Bootstrap registration is
// intentionally absent from this target-facing handler.
func NonProductionHandler(authority *NonProductionAuthority) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+ChallengeEndpoint, func(writer http.ResponseWriter, request *http.Request) {
		body, err := readBoundedRequest(writer, request, false)
		if err != nil {
			writeHTTPError(writer, statusForError(err), err)
			return
		}
		if len(body) != 0 {
			writeHTTPError(writer, http.StatusBadRequest, invalid("challenge request body must be empty"))
			return
		}
		challenge, err := authority.IssueChallenge()
		if err != nil {
			writeHTTPError(writer, statusForError(err), err)
			return
		}
		encoded, err := challenge.CanonicalJSON()
		if err != nil {
			writeHTTPError(writer, http.StatusInternalServerError, err)
			return
		}
		writeHTTPJSON(writer, http.StatusCreated, encoded)
	})
	mux.HandleFunc("POST "+AuthorizationEndpoint, func(writer http.ResponseWriter, request *http.Request) {
		body, err := readBoundedRequest(writer, request, true)
		if err != nil {
			writeHTTPError(writer, statusForError(err), err)
			return
		}
		authorizationRequest, err := ParseAuthorizationRequest(body)
		if err != nil {
			writeHTTPError(writer, statusForError(err), err)
			return
		}
		authorization, err := authority.Authorize(authorizationRequest)
		if err != nil {
			writeHTTPError(writer, statusForError(err), err)
			return
		}
		encoded, err := authorization.CanonicalJSON()
		if err != nil {
			writeHTTPError(writer, http.StatusInternalServerError, err)
			return
		}
		writeHTTPJSON(writer, http.StatusOK, encoded)
	})
	mux.HandleFunc("POST "+OneBootProofEndpoint, func(writer http.ResponseWriter, request *http.Request) {
		body, err := readBoundedRequest(writer, request, true)
		if err != nil {
			writeHTTPError(writer, statusForError(err), err)
			return
		}
		proof, err := ParseOneBootProof(body)
		if err != nil {
			writeHTTPError(writer, statusForError(err), err)
			return
		}
		if err := authority.ProveOneBoot(proof); err != nil {
			writeHTTPError(writer, statusForError(err), err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		if authority == nil {
			writeHTTPError(writer, http.StatusInternalServerError, errors.New("test authority is not configured"))
			return
		}
		if request.TLS == nil || !request.TLS.HandshakeComplete || request.TLS.Version != tls.VersionTLS13 {
			writeHTTPError(writer, http.StatusUpgradeRequired, invalid("TLS 1.3 is required"))
			return
		}
		mux.ServeHTTP(writer, request)
	})
}

// NonProductionAdminConnContext marks only actual Unix-domain connections for
// the bootstrap-registration handler. Supply it as http.Server.ConnContext.
func NonProductionAdminConnContext(ctx context.Context, connection net.Conn) context.Context {
	if unixPeerIsEffectiveUser(connection) {
		return context.WithValue(ctx, unixAdminContextKey{}, true)
	}
	return ctx
}

// NonProductionAdminHandler exposes only bootstrap registration. Filesystem
// ownership and mode on the Unix listener are the administrator boundary.
func NonProductionAdminHandler(authority *NonProductionAuthority) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+BootstrapRegistrationEndpoint, func(writer http.ResponseWriter, request *http.Request) {
		body, err := readBoundedRequest(writer, request, true)
		if err != nil {
			writeHTTPError(writer, statusForError(err), err)
			return
		}
		registration, err := ParseBootstrapRegistration(body)
		if err != nil {
			writeHTTPError(writer, statusForError(err), err)
			return
		}
		publicKey, _ := DecodePublicKey(registration.BootstrapPublicKey)
		if err := authority.RegisterBootstrapKey(registration.LogicalIdentity, publicKey); err != nil {
			writeHTTPError(writer, statusForError(err), err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		if authority == nil {
			writeHTTPError(writer, http.StatusInternalServerError, errors.New("test authority is not configured"))
			return
		}
		if allowed, _ := request.Context().Value(unixAdminContextKey{}).(bool); !allowed {
			writeHTTPError(writer, http.StatusForbidden, errors.New("Unix admin connection is required"))
			return
		}
		mux.ServeHTTP(writer, request)
	})
}

func readBoundedRequest(writer http.ResponseWriter, request *http.Request, requireJSON bool) ([]byte, error) {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if requireJSON {
		if err != nil || mediaType != "application/json" {
			return nil, invalid("Content-Type must be application/json")
		}
	} else if request.Header.Get("Content-Type") != "" && (err != nil || mediaType != "application/json") {
		return nil, invalid("Content-Type must be absent or application/json")
	}
	if request.Body == nil {
		return nil, nil
	}
	reader := http.MaxBytesReader(writer, request.Body, MaxDocumentBytes)
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, tooLarge
		}
		return nil, invalid("request body could not be read")
	}
	return data, nil
}

func writeHTTPJSON(writer http.ResponseWriter, status int, encoded []byte) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}

func writeHTTPError(writer http.ResponseWriter, status int, err error) {
	code := "internal_error"
	switch {
	case errors.Is(err, ErrReplay):
		code = "challenge_replayed"
	case errors.Is(err, ErrExpired):
		code = "challenge_expired"
	case errors.Is(err, ErrUnknownChallenge):
		code = "challenge_unknown"
	case errors.Is(err, ErrUnknownAuthorization):
		code = "authorization_unknown"
	case errors.Is(err, ErrUntrustedBootstrap):
		code = "bootstrap_untrusted"
	case errors.Is(err, ErrUnauthorizedBinding):
		code = "binding_unauthorized"
	case errors.Is(err, ErrBindingMismatch):
		code = "binding_mismatch"
	case errors.Is(err, ErrSignature):
		code = "signature_invalid"
	case errors.Is(err, ErrCapacity):
		code = "challenge_capacity"
	case errors.Is(err, ErrOneBootReplay):
		code = "one_boot_proof_replayed"
	case errors.Is(err, ErrInvalid):
		code = "invalid_request"
	default:
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			code = "request_too_large"
		}
	}
	encoded, marshalErr := marshalBounded(errorResponse{
		SchemaVersion: ErrorSchemaVersion,
		Code:          code,
	})
	if marshalErr != nil {
		encoded = []byte(`{"schema_version":"kaiba.provisioning.rpi5-non-production-boot-authorization-error/v1alpha1","code":"internal_error"}`)
		status = http.StatusInternalServerError
	}
	writeHTTPJSON(writer, status, encoded)
}

func (response errorResponse) canonicalJSON() ([]byte, error) {
	if response.SchemaVersion != ErrorSchemaVersion || sentinelForRemoteCode(response.Code) == nil {
		return nil, invalid("authorization error response is invalid")
	}
	return marshalBounded(response)
}

func parseErrorResponse(data []byte, status int) (*RemoteError, error) {
	var response errorResponse
	if err := parseCanonical(data, &response, func() ([]byte, error) { return response.canonicalJSON() }); err != nil {
		return nil, err
	}
	if statusForRemoteCode(response.Code) != status {
		return nil, invalid("authorization error status and code do not agree")
	}
	return &RemoteError{StatusCode: status, Code: response.Code}, nil
}

func sentinelForRemoteCode(code string) error {
	switch code {
	case "challenge_replayed":
		return ErrReplay
	case "challenge_expired":
		return ErrExpired
	case "challenge_unknown":
		return ErrUnknownChallenge
	case "authorization_unknown":
		return ErrUnknownAuthorization
	case "bootstrap_untrusted":
		return ErrUntrustedBootstrap
	case "binding_unauthorized":
		return ErrUnauthorizedBinding
	case "binding_mismatch":
		return ErrBindingMismatch
	case "signature_invalid":
		return ErrSignature
	case "challenge_capacity":
		return ErrCapacity
	case "one_boot_proof_replayed":
		return ErrOneBootReplay
	case "invalid_request":
		return ErrInvalid
	case "request_too_large":
		return ErrInvalid
	case "internal_error":
		return errors.New("non-production authorization server internal error")
	default:
		return nil
	}
}

func statusForRemoteCode(code string) int {
	switch code {
	case "challenge_replayed", "one_boot_proof_replayed":
		return http.StatusConflict
	case "challenge_expired":
		return http.StatusGone
	case "challenge_unknown", "authorization_unknown":
		return http.StatusNotFound
	case "bootstrap_untrusted", "binding_unauthorized", "binding_mismatch", "signature_invalid":
		return http.StatusForbidden
	case "challenge_capacity":
		return http.StatusServiceUnavailable
	case "internal_error":
		return http.StatusInternalServerError
	case "invalid_request":
		return http.StatusBadRequest
	case "request_too_large":
		return http.StatusRequestEntityTooLarge
	default:
		return 0
	}
}

func statusForError(err error) int {
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, ErrReplay), errors.Is(err, ErrOneBootReplay):
		return http.StatusConflict
	case errors.Is(err, ErrExpired):
		return http.StatusGone
	case errors.Is(err, ErrUnknownChallenge), errors.Is(err, ErrUnknownAuthorization):
		return http.StatusNotFound
	case errors.Is(err, ErrUntrustedBootstrap), errors.Is(err, ErrUnauthorizedBinding),
		errors.Is(err, ErrBindingMismatch), errors.Is(err, ErrSignature):
		return http.StatusForbidden
	case errors.Is(err, ErrCapacity):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrInvalid):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}
