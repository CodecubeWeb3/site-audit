package crawl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	robotstxt "github.com/temoto/robotstxt"
	"golang.org/x/net/html"
)

// PageResult captures the information learned about a single crawled page.
type PageResult struct {
	URL        string
	StatusCode int
	Title      string
	Links      []string
	Canonical  string
	Hash       string
}

// Result aggregates the crawler results.
type Result struct {
	Pages         map[string]*PageResult
	Graph         map[string][]string
	Redirects     map[string][]string
	Sitemaps      []string
	Orphaned      []string
	Errors        map[string]error
	MirroredFiles map[string]string
}

// Config defines crawler behaviour.
type Config struct {
	MaxDepth        int
	MaxPages        int
	Delay           time.Duration
	UserAgent       string
	RespectRobots   bool
	OutputDir       string
	AllowedHosts    []string
	FollowRedirects bool
}

// Crawler is a polite, consent-first HTTP crawler.
type Crawler struct {
	client *http.Client
	cfg    Config
}

// New creates a new crawler with the provided HTTP client and configuration.
func New(client *http.Client, cfg Config) (*Crawler, error) {
	if client == nil {
		return nil, errors.New("http client must not be nil")
	}
	if cfg.MaxDepth < 0 {
		return nil, errors.New("max depth cannot be negative")
	}
	if cfg.MaxPages <= 0 {
		cfg.MaxPages = 100
	}
	if cfg.Delay <= 0 {
		cfg.Delay = 500 * time.Millisecond
	}
	if cfg.OutputDir == "" {
		cfg.OutputDir = "artifacts/mirror"
	}
	return &Crawler{client: client, cfg: cfg}, nil
}

// Crawl performs a crawl starting at the provided root URL.
func (c *Crawler) Crawl(ctx context.Context, root string) (*Result, error) {
	rootURL, err := url.Parse(root)
	if err != nil {
		return nil, fmt.Errorf("parse root: %w", err)
	}

	res := &Result{
		Pages:         map[string]*PageResult{},
		Graph:         map[string][]string{},
		Redirects:     map[string][]string{},
		Errors:        map[string]error{},
		MirroredFiles: map[string]string{},
	}

	var mu sync.Mutex
	visited := map[string]bool{}
	queue := []struct {
		URL   *url.URL
		Depth int
	}{{rootURL, 0}}

	var robots *robotstxt.RobotsData
	if c.cfg.RespectRobots {
		robots, _ = c.fetchRobots(ctx, rootURL)
		if robots != nil {
			res.Sitemaps = append(res.Sitemaps, robots.Sitemaps...)
		}
	}

	sitemapLocations, sitemapURLs := c.discoverSitemaps(ctx, rootURL, robots)
	res.Sitemaps = append(res.Sitemaps, sitemapLocations...)
	seenGraph := map[string]struct{}{}

	for len(queue) > 0 && len(res.Pages) < c.cfg.MaxPages {
		current := queue[0]
		queue = queue[1:]

		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}

		if c.cfg.MaxDepth > 0 && current.Depth > c.cfg.MaxDepth {
			continue
		}

		normalized := canonicalURL(current.URL)
		if visited[normalized] {
			continue
		}
		visited[normalized] = true

		if !c.hostAllowed(current.URL.Hostname()) {
			continue
		}

		if robots != nil && !robots.TestAgent(current.URL.Path, c.cfg.UserAgent) {
			continue
		}

		time.Sleep(c.cfg.Delay)

		page, links, redirectChain, bodyHash, mirrorPath, err := c.fetchPage(ctx, current.URL)
		if err != nil {
			mu.Lock()
			res.Errors[normalized] = err
			mu.Unlock()
			continue
		}

		mu.Lock()
		res.Pages[normalized] = page
		res.Graph[normalized] = links
		if len(redirectChain) > 0 {
			res.Redirects[normalized] = redirectChain
		}
		if mirrorPath != "" {
			res.MirroredFiles[normalized] = mirrorPath
		}
		mu.Unlock()

		for _, link := range links {
			if _, ok := seenGraph[normalized+"->"+link]; !ok {
				seenGraph[normalized+"->"+link] = struct{}{}
			}

			u, err := url.Parse(link)
			if err != nil {
				continue
			}
			if !u.IsAbs() {
				u = current.URL.ResolveReference(u)
			}
			u.Fragment = ""
			norm := canonicalURL(u)
			if visited[norm] {
				continue
			}
			if !c.hostAllowed(u.Hostname()) {
				continue
			}
			queue = append(queue, struct {
				URL   *url.URL
				Depth int
			}{u, current.Depth + 1})
		}

		if page.Canonical != "" {
			norm := strings.TrimSpace(page.Canonical)
			if _, ok := res.Pages[norm]; ok && norm != normalized {
				res.Redirects[normalized] = append(res.Redirects[normalized], norm)
			}
		}

		if bodyHash != "" {
			mu.Lock()
			res.Pages[normalized].Hash = bodyHash
			mu.Unlock()
		}
	}

	res.Orphaned = c.findOrphans(res.Pages, sitemapURLs)
	return res, nil
}

func (c *Crawler) fetchRobots(ctx context.Context, root *url.URL) (*robotstxt.RobotsData, error) {
	robotsURL := &url.URL{}
	*robotsURL = *root
	robotsURL.Path = "/robots.txt"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, robotsURL.String(), nil)
	if err != nil {
		return nil, err
	}
	if c.cfg.UserAgent != "" {
		req.Header.Set("User-Agent", c.cfg.UserAgent)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("robots fetch returned status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	return robotstxt.FromBytes(data)
}

func (c *Crawler) discoverSitemaps(ctx context.Context, root *url.URL, robots *robotstxt.RobotsData) ([]string, []string) {
	locations := make([]string, 0)
	if robots != nil {
		locations = append(locations, robots.Sitemaps...)
	}

	defaultSitemap := &url.URL{}
	*defaultSitemap = *root
	defaultSitemap.Path = "/sitemap.xml"
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	sitemapEntries := make([]string, 0)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, defaultSitemap.String(), nil)
	if err != nil {
		return dedupeStrings(locations), dedupeStrings(sitemapEntries)
	}
	if c.cfg.UserAgent != "" {
		req.Header.Set("User-Agent", c.cfg.UserAgent)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return dedupeStrings(locations), dedupeStrings(sitemapEntries)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return dedupeStrings(locations), dedupeStrings(sitemapEntries)
	}

	if ct := resp.Header.Get("Content-Type"); !strings.Contains(strings.ToLower(ct), "xml") {
		return dedupeStrings(locations), dedupeStrings(sitemapEntries)
	}

	buf, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return dedupeStrings(locations), dedupeStrings(sitemapEntries)
	}

	if len(buf) > 0 {
		locations = append(locations, defaultSitemap.String())
	}

	sitemapEntries = append(sitemapEntries, extractSitemapURLs(buf)...)
	return dedupeStrings(locations), dedupeStrings(sitemapEntries)
}

func (c *Crawler) fetchPage(ctx context.Context, pageURL *url.URL) (*PageResult, []string, []string, string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL.String(), nil)
	if err != nil {
		return nil, nil, nil, "", "", err
	}
	if c.cfg.UserAgent != "" {
		req.Header.Set("User-Agent", c.cfg.UserAgent)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, nil, "", "", err
	}
	defer resp.Body.Close()

	redirectChain := []string{}
	if resp.Request != nil && resp.Request.URL.String() != pageURL.String() {
		redirectChain = append(redirectChain, resp.Request.URL.String())
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, nil, redirectChain, "", "", err
	}

	hash := sha256.Sum256(body)
	hashHex := hex.EncodeToString(hash[:])

	links := extractLinks(pageURL, body)
	title, canonical := extractMeta(body)

	var mirrorPath string
	if err := c.mirrorBody(pageURL, body, hashHex); err == nil {
		mirrorPath = c.mirrorFilename(pageURL, hashHex)
	}

	return &PageResult{
		URL:        pageURL.String(),
		StatusCode: resp.StatusCode,
		Title:      title,
		Links:      links,
		Canonical:  canonical,
		Hash:       hashHex,
	}, links, redirectChain, hashHex, mirrorPath, nil
}

func (c *Crawler) mirrorBody(pageURL *url.URL, body []byte, hash string) error {
	if c.cfg.OutputDir == "" {
		return nil
	}

	if err := os.MkdirAll(c.cfg.OutputDir, 0o755); err != nil {
		return err
	}

	filename := c.mirrorFilename(pageURL, hash)
	return os.WriteFile(filename, body, 0o644)
}

func (c *Crawler) mirrorFilename(pageURL *url.URL, hash string) string {
	name := pageURL.Host + strings.ReplaceAll(pageURL.Path, "/", "_")
	if name == "" || name == pageURL.Host {
		name = pageURL.Host + "_index"
	}
	return filepath.Join(c.cfg.OutputDir, fmt.Sprintf("%s_%s.html", name, hash[:8]))
}

func (c *Crawler) findOrphans(pages map[string]*PageResult, sitemap []string) []string {
	if len(sitemap) == 0 {
		return nil
	}

	pageSet := map[string]struct{}{}
	for url := range pages {
		pageSet[url] = struct{}{}
	}

	var orphans []string
	for _, u := range sitemap {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if _, ok := pageSet[u]; !ok {
			orphans = append(orphans, u)
		}
	}
	sort.Strings(orphans)
	return orphans
}

func (c *Crawler) hostAllowed(host string) bool {
	if len(c.cfg.AllowedHosts) == 0 {
		return true
	}
	for _, allowed := range c.cfg.AllowedHosts {
		if strings.EqualFold(allowed, host) {
			return true
		}
	}
	return false
}

func canonicalURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	n := *u
	n.Fragment = ""
	n.Path = path.Clean(n.Path)
	if n.Path == "." {
		n.Path = "/"
	}
	return n.String()
}

func extractLinks(base *url.URL, body []byte) []string {
	tokens := html.NewTokenizer(strings.NewReader(string(body)))
	var links []string
	for {
		t := tokens.Next()
		switch t {
		case html.ErrorToken:
			return dedupeStrings(links)
		case html.StartTagToken, html.SelfClosingTagToken:
			tag, hasAttr := tokens.TagName()
			if string(tag) != "a" && string(tag) != "link" {
				continue
			}
			for hasAttr {
				key, val, more := tokens.TagAttr()
				hasAttr = more
				if string(key) != "href" {
					continue
				}
				link := string(val)
				if link == "" || strings.HasPrefix(link, "javascript:") {
					continue
				}
				u, err := url.Parse(link)
				if err != nil {
					continue
				}
				if !u.IsAbs() && base != nil {
					u = base.ResolveReference(u)
				}
				u.Fragment = ""
				links = append(links, u.String())
			}
		}
	}
}

func extractMeta(body []byte) (title string, canonical string) {
	tokens := html.NewTokenizer(strings.NewReader(string(body)))
	for {
		t := tokens.Next()
		switch t {
		case html.ErrorToken:
			return title, canonical
		case html.StartTagToken:
			tag, hasAttr := tokens.TagName()
			name := string(tag)
			if name == "title" {
				tokens.Next()
				title = strings.TrimSpace(tokens.Token().Data)
			}
			if name == "link" {
				var rel, href string
				for hasAttr {
					key, val, more := tokens.TagAttr()
					hasAttr = more
					k := string(key)
					if k == "rel" {
						rel = string(val)
					}
					if k == "href" {
						href = string(val)
					}
				}
				if strings.EqualFold(rel, "canonical") {
					canonical = strings.TrimSpace(href)
				}
			}
		}
	}
}

func extractSitemapURLs(xmlData []byte) []string {
	const locTag = "<loc>"
	const endTag = "</loc>"
	var urls []string
	data := string(xmlData)
	for {
		start := strings.Index(strings.ToLower(data), locTag)
		if start == -1 {
			break
		}
		data = data[start+len(locTag):]
		end := strings.Index(strings.ToLower(data), endTag)
		if end == -1 {
			break
		}
		urls = append(urls, strings.TrimSpace(data[:end]))
		data = data[end+len(endTag):]
	}
	return dedupeStrings(urls)
}

func dedupeStrings(values []string) []string {
	seen := map[string]struct{}{}
	var result []string
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		result = append(result, v)
	}
	return result
}
