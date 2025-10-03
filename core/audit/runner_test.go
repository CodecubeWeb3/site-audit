package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CodecubeWeb3/site-audit/core/config"
)

func TestRunnerProducesArtifacts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.Write([]byte("User-agent: *\nAllow: /"))
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Server", "TestServer")
			w.Write([]byte("<html><head><title>Test</title></head><body>React router-link</body></html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Reporting.OutputDir = filepath.Join(tmpDir, "artifacts")
	cfg.Crawler.CrawlDelay = 10 * time.Millisecond
	cfg.Crawler.MaxDepth = 1
	cfg.Targets = []config.Target{{
		URL:          srv.URL,
		AllowedHosts: []string{hostOnly(srv.URL)},
	}}

	runner := NewRunner()
	result, err := runner.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("run error: %v", err)
	}

	if len(result.Targets) != 1 {
		t.Fatalf("expected single target result")
	}
	if result.Targets[0].HTTP == nil {
		t.Fatalf("expected http result")
	}
	if result.Targets[0].SEO == nil {
		t.Fatalf("expected seo result")
	}
	if result.Targets[0].Accessibility == nil {
		t.Fatalf("expected accessibility result")
	}
	if result.Targets[0].Assets == nil {
		t.Fatalf("expected assets result")
	}
	if result.Targets[0].Performance == nil {
		t.Fatalf("expected performance result")
	}
	if result.Targets[0].Security == nil {
		t.Fatalf("expected security hygiene result")
	}

	runPath := filepath.Join(cfg.Reporting.OutputDir, "run.json")
	if _, err := os.Stat(runPath); err != nil {
		t.Fatalf("run.json missing: %v", err)
	}
}

func hostOnly(raw string) string {
	u, _ := url.Parse(raw)
	host := u.Host
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}
	return host
}
