package securitypassive

import (
	"testing"

	"github.com/CodecubeWeb3/site-audit/modules/httpcheck"
)

func TestAnalyzeDetectsIssues(t *testing.T) {
	httpRes := &httpcheck.Result{Headers: map[string]string{
		"server":       "nginx",
		"x-powered-by": "php/7.4",
		"set-cookie":   "id=1; Path=/",
	}}
	body := "Index of /secret .well-known/security.txt"
	res := Analyze(httpRes, body)
	if len(res.ExposedHeaders) != 2 {
		t.Fatalf("expected exposed headers, got %#v", res.ExposedHeaders)
	}
	if len(res.CookieIssues) == 0 {
		t.Fatal("expected cookie issues")
	}
	if len(res.WellKnownHints) == 0 {
		t.Fatal("expected well-known hints")
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected summary findings")
	}
}
