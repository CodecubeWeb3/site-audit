package fingerprint

import (
	"net/http"
	"testing"
)

func TestAnalyzeDetectsFrameworks(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "nginx")
	headers.Add("X-Powered-By", "PHP/8.1")
	headers.Add("X-Powered-By", "Express")

	html := `<html><head><script>var __NEXT_DATA__ = {};</script></head><body><div id="app">React Angular Vue Svelte router-link</div><script src="/static/app.js.map"></script><link rel="stylesheet" href="/wp-content/themes/theme/style.css"></body></html>`

	res := Analyze(headers, html)

	if res.Server != "nginx" {
		t.Fatalf("expected nginx server, got %s", res.Server)
	}
	if len(res.PoweredBy) != 2 {
		t.Fatalf("expected two powered-by headers, got %d", len(res.PoweredBy))
	}
	if len(res.JavaScriptFramework) != 4 {
		t.Fatalf("expected all frameworks detected, got %#v", res.JavaScriptFramework)
	}
	if len(res.CMSHints) == 0 || res.CMSHints[0] != "WordPress" {
		t.Fatalf("expected WordPress hint")
	}
	if res.SPARouter != "detected" {
		t.Fatalf("expected router detection")
	}
	if len(res.SourceMaps) != 1 {
		t.Fatalf("expected source map detection")
	}
}
