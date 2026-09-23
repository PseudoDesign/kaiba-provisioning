package livestation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type ObservationHandler struct {
	source       ObservationSource
	expectedHost string
}

func NewObserverHandler(source ObservationSource, expectedHost string) (http.Handler, error) {
	if source == nil {
		return nil, errors.New("observation source is required")
	}
	if err := ValidateListenAddress(expectedHost); err != nil {
		return nil, fmt.Errorf("expected Host: %w", err)
	}
	return &ObservationHandler{source: source, expectedHost: expectedHost}, nil
}

func (handler *ObservationHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(response.Header())
	if request.Host != handler.expectedHost {
		writeProblem(response, http.StatusMisdirectedRequest, "invalid_host", "Invalid Host", "The request Host does not identify this loopback station.", 0)
		return
	}
	if request.URL.RawQuery != "" {
		writeProblem(response, http.StatusBadRequest, "query_not_allowed", "Query not allowed", "Live station endpoints do not accept query parameters.", 0)
		return
	}
	switch request.URL.Path {
	case "/":
		serveAsset(response, request, "index.html", "text/html; charset=utf-8")
	case "/app.js":
		serveAsset(response, request, "app.js", "text/javascript; charset=utf-8")
	case "/campaign.js":
		serveAsset(response, request, "campaign.js", "text/javascript; charset=utf-8")
	case "/styles.css":
		serveAsset(response, request, "styles.css", "text/css; charset=utf-8")
	case "/runtime-config.json":
		if request.Method != http.MethodGet {
			methodNotAllowed(response, http.MethodGet)
			return
		}
		writeJSON(response, http.StatusOK, ObservationRuntime{
			SchemaVersion: ObservationRuntimeSchemaVersion, StateSchemaVersion: ObservationStateSchemaVersion,
			ExpectedOrigin: "http://" + handler.expectedHost, StateEndpoint: "/api/v1/state",
			ReadOnly: true, RefreshIntervalSeconds: 5,
		})
	case "/api/v1/state":
		if request.Method != http.MethodGet {
			methodNotAllowed(response, http.MethodGet)
			return
		}
		// Bound lock wait plus the authority call below the server write timeout.
		ctx, cancel := context.WithTimeout(request.Context(), 20*time.Second)
		defer cancel()
		state, err := handler.source.Current(ctx)
		if err != nil {
			writeProblem(response, http.StatusServiceUnavailable, "state_unavailable", "State unavailable", "Station observation could not be read.", 0)
			return
		}
		writeJSON(response, http.StatusOK, state)
	case "/api/v1/actions":
		writeProblem(response, http.StatusForbidden, "read_only", "Read-only station", "This station only observes recorded status and cannot perform workflow actions.", 0)
	default:
		writeProblem(response, http.StatusNotFound, "not_found", "Not found", "The requested resource does not exist.", 0)
	}
}

func ListenAndServeObserver(ctx context.Context, address string, source ObservationSource) error {
	return listenAndServe(ctx, address, func(expectedHost string) (http.Handler, error) {
		return NewObserverHandler(source, expectedHost)
	}, 25*time.Second)
}
