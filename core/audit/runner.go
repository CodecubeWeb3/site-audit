package audit

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodecubeWeb3/site-audit/core/config"
	"github.com/CodecubeWeb3/site-audit/core/model"
	"github.com/CodecubeWeb3/site-audit/core/reporting"
	"github.com/CodecubeWeb3/site-audit/modules/accessibility"
	"github.com/CodecubeWeb3/site-audit/modules/assets"
	"github.com/CodecubeWeb3/site-audit/modules/crawl"
	"github.com/CodecubeWeb3/site-audit/modules/dnsresolver"
	"github.com/CodecubeWeb3/site-audit/modules/fingerprint"
	"github.com/CodecubeWeb3/site-audit/modules/httpcheck"
	"github.com/CodecubeWeb3/site-audit/modules/perf"
	"github.com/CodecubeWeb3/site-audit/modules/securitypassive"
	"github.com/CodecubeWeb3/site-audit/modules/seo"
	"github.com/CodecubeWeb3/site-audit/modules/tlsinspect"
)

// Runner coordinates passive auditing modules.
type Runner struct {
	HTTPClient *http.Client
}

// NewRunner initialises a runner with a default HTTP client.
func NewRunner() *Runner {
	return &Runner{HTTPClient: &http.Client{Timeout: 20 * time.Second}}
}

// Run executes passive modules and writes reports to disk.
func (r *Runner) Run(ctx context.Context, cfg config.Config) (*model.RunResult, error) {
	if cfg.Mode == config.ModeFull || cfg.Mode == config.ModeSafeActive {
		return nil, fmt.Errorf("active modules require signed consent; run aborted")
	}
	if len(cfg.Targets) == 0 {
		return nil, fmt.Errorf("no targets provided")
	}

	res := &model.RunResult{
		StartedAt: time.Now().UTC(),
		Mode:      cfg.Mode,
		Metadata:  map[string]string{},
	}

	client := r.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: cfg.HTTP.Timeout}
	}

	for _, target := range cfg.Targets {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}

		targetRes := model.TargetResult{Target: target}
		parsedURL, err := url.Parse(target.URL)
		if err != nil {
			targetRes.Errors = append(targetRes.Errors, fmt.Sprintf("parse target url: %v", err))
			res.Targets = append(res.Targets, targetRes)
			continue
		}

		crawlCfg := crawl.Config{
			MaxDepth:        minNonZero(target.MaxDepth, cfg.Crawler.MaxDepth),
			MaxPages:        cfg.Crawler.MaxPages,
			Delay:           cfg.Crawler.CrawlDelay,
			UserAgent:       cfg.HTTP.UserAgent,
			RespectRobots:   cfg.HTTP.RespectRobots,
			OutputDir:       filepath.Join(cfg.Reporting.OutputDir, "mirror"),
			AllowedHosts:    target.AllowedHosts,
			FollowRedirects: cfg.Crawler.FollowRedirects,
		}
		crawler, err := crawl.New(client, crawlCfg)
		if err != nil {
			targetRes.Errors = append(targetRes.Errors, fmt.Sprintf("init crawler: %v", err))
		} else {
			crawlRes, err := crawler.Crawl(ctx, target.URL)
			if err != nil {
				targetRes.Errors = append(targetRes.Errors, fmt.Sprintf("crawl error: %v", err))
			} else {
				targetRes.Crawl = crawlRes
			}
		}

		auditor := httpcheck.NewAuditor(client)
		httpRes, err := auditor.Audit(ctx, target.URL)
		if err != nil {
			targetRes.Errors = append(targetRes.Errors, fmt.Sprintf("http audit: %v", err))
		} else {
			targetRes.HTTP = httpRes
		}

		inspector := tlsinspect.NewInspector()
		if inspector.TLSConfig != nil {
			inspector.TLSConfig.InsecureSkipVerify = false
		}
		tlsHost := parsedURL.Host
		if !strings.Contains(tlsHost, ":") {
			tlsHost = tlsHost + ":443"
		}
		tlsRes, err := inspector.Inspect(ctx, tlsHost)
		if err != nil {
			targetRes.Errors = append(targetRes.Errors, fmt.Sprintf("tls inspect: %v", err))
		} else {
			targetRes.TLS = tlsRes
		}

		dnsRes, err := dnsresolver.NewResolver().Resolve(ctx, parsedURL.Hostname())
		if err != nil {
			targetRes.Errors = append(targetRes.Errors, fmt.Sprintf("dns resolve: %v", err))
		} else {
			targetRes.DNS = dnsRes
		}

		body, err := fetchBody(ctx, client, target.URL, cfg.HTTP.UserAgent)
		if err != nil {
			targetRes.Errors = append(targetRes.Errors, fmt.Sprintf("fetch body: %v", err))
		}
		fingerprintRes := fingerprint.Analyze(copyHeaders(targetRes.HTTP), body)
		targetRes.Fingerprint = fingerprintRes

		if body != "" {
			seoRes := seo.Analyze(body)
			targetRes.SEO = &seoRes

			accessibilityRes := accessibility.Audit(body)
			targetRes.Accessibility = &accessibilityRes

			assetsRes := assets.Inventory(target.URL, body)
			targetRes.Assets = &assetsRes

			perfRes := perf.Analyze(body)
			targetRes.Performance = &perfRes

			secRes := securitypassive.Analyze(targetRes.HTTP, body)
			targetRes.Security = &secRes
		}

		targetRes.ArtifactsDir = cfg.Reporting.OutputDir
		res.Targets = append(res.Targets, targetRes)
	}

	res.Completed = time.Now().UTC()

	if err := reporting.WriteJSON(filepath.Join(cfg.Reporting.OutputDir, "run.json"), res); err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("write run.json: %v", err))
	}
	if err := reporting.WriteHTML(filepath.Join(cfg.Reporting.OutputDir, "report.html"), res); err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("write report.html: %v", err))
	}

	return res, nil
}

func fetchBody(ctx context.Context, client *http.Client, target string, userAgent string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	buf, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

func copyHeaders(res *httpcheck.Result) http.Header {
	headers := http.Header{}
	if res == nil {
		return headers
	}
	for k, v := range res.Headers {
		headers.Set(http.CanonicalHeaderKey(k), v)
	}
	return headers
}

func minNonZero(values ...int) int {
	min := 0
	for _, v := range values {
		if v == 0 {
			continue
		}
		if min == 0 || v < min {
			min = v
		}
	}
	return min
}
