package httpcheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuditDetectsMissingHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Alt-Svc", "h3=\":443\"")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	auditor := NewAuditor(nil)
	res, err := auditor.Audit(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("audit error: %v", err)
	}

	if len(res.MissingSecurity) == 6 { // expecting all but CSP missing
		// ok
	} else {
		t.Fatalf("unexpected missing headers count: %d", len(res.MissingSecurity))
	}

	if res.CORS.AllowOrigin != "*" || !res.CORS.AllowCredentials {
		t.Fatalf("unexpected CORS result: %#v", res.CORS)
	}
	if res.CORS.Issues[0] != "wildcard origin with credentials" {
		t.Fatalf("expected wildcard issue, got %#v", res.CORS.Issues)
	}

	if res.Compression != "gzip" {
		t.Fatalf("expected gzip compression, got %s", res.Compression)
	}

	if !res.SupportsHTTP3 {
		t.Fatalf("expected HTTP/3 support due to Alt-Svc header")
	}
}
