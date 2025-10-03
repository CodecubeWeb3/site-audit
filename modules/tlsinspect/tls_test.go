package tlsinspect

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInspectorParsesCertificates(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	inspector := NewInspector()
	inspector.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	res, err := inspector.Inspect(context.Background(), srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}

	if res.Version == "" || res.CipherSuite == "" {
		t.Fatalf("expected version and cipher suite, got %#v", res)
	}

	if len(res.Certificates) == 0 {
		t.Fatalf("expected at least one certificate")
	}
}

func TestDetectMixedContent(t *testing.T) {
	html := `<html><body><img src="http://example.com/image.png"><script src="https://secure"></script></body></html>`
	findings := DetectMixedContent(html)
	if len(findings) != 1 {
		t.Fatalf("expected one mixed content finding, got %d", len(findings))
	}
}
