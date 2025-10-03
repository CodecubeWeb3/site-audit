package httpcheck

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Result represents findings from the HTTP inspection module.
type Result struct {
	URL             string
	Headers         map[string]string
	MissingSecurity []string
	CORS            CORSResult
	Compression     string
	Cache           CacheResult
	HTTPVersion     string
	SupportsHTTP3   bool
}

// CORSResult captures common misconfiguration indicators.
type CORSResult struct {
	AllowOrigin      string
	AllowCredentials bool
	Issues           []string
}

// CacheResult summarises cache related headers.
type CacheResult struct {
	CacheControl string
	ETag         string
	LastModified string
	Vary         string
}

// Auditor performs HTTP header audits.
type Auditor struct {
	Client *http.Client
}

// NewAuditor creates an auditor with safe defaults.
func NewAuditor(client *http.Client) *Auditor {
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.DisableCompression = true
		client = &http.Client{Timeout: 15 * time.Second, Transport: transport}
	}
	return &Auditor{Client: client}
}

// Audit executes the HTTP checks against the provided URL.
func (a *Auditor) Audit(ctx context.Context, target string) (*Result, error) {
	if _, err := url.ParseRequestURI(target); err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "site-audit/0.1")

	resp, err := a.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	headers := map[string]string{}
	for k, v := range resp.Header {
		headers[strings.ToLower(k)] = strings.Join(v, ", ")
	}

	missing := findMissingHeaders(headers)
	cors := evaluateCORS(headers)
	compression := detectCompression(headers, resp.Uncompressed)
	cache := CacheResult{
		CacheControl: headers["cache-control"],
		ETag:         headers["etag"],
		LastModified: headers["last-modified"],
		Vary:         headers["vary"],
	}

	supportsHTTP3 := strings.Contains(strings.ToLower(headers["alt-svc"]), "h3")

	return &Result{
		URL:             target,
		Headers:         headers,
		MissingSecurity: missing,
		CORS:            cors,
		Compression:     compression,
		Cache:           cache,
		HTTPVersion:     resp.Proto,
		SupportsHTTP3:   supportsHTTP3,
	}, nil
}

var requiredHeaders = []string{
	"content-security-policy",
	"strict-transport-security",
	"x-frame-options",
	"x-content-type-options",
	"referrer-policy",
	"permissions-policy",
	"x-xss-protection",
}

func findMissingHeaders(headers map[string]string) []string {
	var missing []string
	for _, header := range requiredHeaders {
		if _, ok := headers[header]; !ok {
			missing = append(missing, header)
		}
	}
	return missing
}

func evaluateCORS(headers map[string]string) CORSResult {
	origin := headers["access-control-allow-origin"]
	allowCreds := strings.Contains(strings.ToLower(headers["access-control-allow-credentials"]), "true")
	issues := []string{}
	if origin == "*" && allowCreds {
		issues = append(issues, "wildcard origin with credentials")
	}
	if origin == "null" {
		issues = append(issues, "null origin allowed")
	}
	if origin == "" {
		issues = append(issues, "no cors headers present")
	}
	return CORSResult{AllowOrigin: origin, AllowCredentials: allowCreds, Issues: issues}
}

func detectCompression(headers map[string]string, uncompressed bool) string {
	encoding := strings.ToLower(headers["content-encoding"])
	switch {
	case strings.Contains(encoding, "br"):
		return "brotli"
	case strings.Contains(encoding, "gzip"):
		return "gzip"
	case strings.Contains(encoding, "deflate"):
		return "deflate"
	default:
		if uncompressed && encoding == "" {
			return "decompressed"
		}
		return "none"
	}
}
