package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kubev2v/migration-planner/pkg/middleware"
	"github.com/kubev2v/migration-planner/pkg/requestid"
)

func nopHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func TestRequestID_SetsResponseHeader(t *testing.T) {
	handler := middleware.RequestID(http.HandlerFunc(nopHandler))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Header().Get(middleware.RequestIDHeader) == "" {
		t.Fatal("expected X-Request-ID response header to be set, got empty string")
	}
}

func TestRequestID_EchosIncomingHeader(t *testing.T) {
	const clientID = "my-client-request-id"

	handler := middleware.RequestID(http.HandlerFunc(nopHandler))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(middleware.RequestIDHeader, clientID)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get(middleware.RequestIDHeader); got != clientID {
		t.Fatalf("expected X-Request-ID %q, got %q", clientID, got)
	}
}

func TestGetRequestIDFromRequest(t *testing.T) {
	var got string
	capture := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = middleware.GetRequestIDFromRequest(r)
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.RequestID(capture)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got == "" {
		t.Fatal("expected GetRequestIDFromRequest to return non-empty ID")
	}
	if got != rec.Header().Get(middleware.RequestIDHeader) {
		t.Fatalf("GetRequestIDFromRequest returned %q, want %q", got, rec.Header().Get(middleware.RequestIDHeader))
	}
}

func TestRequestID_ResponseHeaderMatchesContext(t *testing.T) {
	var contextID string
	capture := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextID = requestid.FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.RequestID(capture)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	headerID := rec.Header().Get(middleware.RequestIDHeader)
	if headerID == "" {
		t.Fatal("expected X-Request-ID response header to be set")
	}
	if headerID != contextID {
		t.Fatalf("response header %q does not match context value %q", headerID, contextID)
	}
}
