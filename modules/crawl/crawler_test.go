package crawl

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
)

func TestCrawlerRespectsScopeAndBuildsGraph(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("User-agent: *\nAllow: /\nSitemap: " + srvURL(r).ResolveReference(&url.URL{Path: "/sitemap.xml"}).String()))
		case "/sitemap.xml":
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte("<urlset><url><loc>" + srvURL(r).ResolveReference(&url.URL{Path: "/"}).String() + "</loc></url><url><loc>https://example.com/orphan</loc></url></urlset>"))
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><head><title>Home</title><link rel=\"canonical\" href=\"" + srvURL(r).String() + "\"></head><body><a href=\"/about\">About</a></body></html>"))
		case "/about":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><head><title>About</title></head><body><a href=\"/\">Home</a></body></html>"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	host := strings.Split(srv.URL, "//")[1]
	client := &http.Client{Timeout: 5 * time.Second}
	tmpDir := t.TempDir()

	crawler, err := New(client, Config{
		MaxDepth:        2,
		MaxPages:        10,
		Delay:           10 * time.Millisecond,
		UserAgent:       "site-audit-test",
		RespectRobots:   true,
		OutputDir:       tmpDir,
		AllowedHosts:    []string{strings.Split(host, ":")[0]},
		FollowRedirects: true,
	})
	if err != nil {
		t.Fatalf("new crawler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := crawler.Crawl(ctx, srv.URL)
	if err != nil {
		t.Fatalf("crawl error: %v", err)
	}

	if len(res.Pages) != 2 {
		t.Fatalf("expected 2 pages, got %d", len(res.Pages))
	}

	rootURL := canonicalFromString(srv.URL)
	page := res.Pages[rootURL]
	if page == nil {
		t.Fatalf("missing root page")
	}
	if page.Title != "Home" {
		t.Fatalf("unexpected title: %s", page.Title)
	}

	if len(res.Orphaned) != 1 || res.Orphaned[0] != "https://example.com/orphan" {
		t.Fatalf("unexpected orphaned pages: %#v", res.Orphaned)
	}

	if len(res.Graph[rootURL]) == 0 {
		t.Fatalf("missing graph entry for root")
	}

	if _, err := os.Stat(filepath.Join(tmpDir, filepath.Base(res.MirroredFiles[rootURL]))); err != nil {
		t.Fatalf("expected mirrored file: %v", err)
	}
}

func srvURL(r *http.Request) *url.URL {
	u := &url.URL{}
	*u = *r.URL
	u.Scheme = "http"
	u.Host = r.Host
	return u
}

func canonicalFromString(raw string) string {
	u, _ := url.Parse(raw)
	return canonicalURL(u)
}
