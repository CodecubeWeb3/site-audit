package model

import (
	"time"

	"github.com/CodecubeWeb3/site-audit/core/config"
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

// RunResult contains the aggregated results from a scan execution.
type RunResult struct {
	StartedAt time.Time         `json:"startedAt"`
	Completed time.Time         `json:"completed"`
	Mode      config.Mode       `json:"mode"`
	Targets   []TargetResult    `json:"targets"`
	Errors    []string          `json:"errors"`
	Metadata  map[string]string `json:"metadata"`
}

// TargetResult summarises checks for a single target.
type TargetResult struct {
	Target        config.Target           `json:"target"`
	Crawl         *crawl.Result           `json:"crawl,omitempty"`
	HTTP          *httpcheck.Result       `json:"http,omitempty"`
	TLS           *tlsinspect.Result      `json:"tls,omitempty"`
	DNS           *dnsresolver.Result     `json:"dns,omitempty"`
	Fingerprint   fingerprint.Result      `json:"fingerprint"`
	SEO           *seo.Result             `json:"seo,omitempty"`
	Accessibility *accessibility.Result   `json:"accessibility,omitempty"`
	Assets        *assets.Result          `json:"assets,omitempty"`
	Performance   *perf.Result            `json:"performance,omitempty"`
	Security      *securitypassive.Result `json:"security,omitempty"`
	Errors        []string                `json:"errors,omitempty"`
	ArtifactsDir  string                  `json:"artifactsDir"`
}
