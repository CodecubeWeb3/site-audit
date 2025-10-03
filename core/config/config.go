package config

import (
"encoding/json"
"errors"
"fmt"
"io"
"os"
"path/filepath"
"strings"
"time"

"gopkg.in/yaml.v3"
)

// Mode represents the scanning mode requested by the operator.
type Mode string

const (
// ModePassive performs passive-only checks.
ModePassive Mode = "passive"
// ModeSafeActive enables safe-active modules with consent.
ModeSafeActive Mode = "safe-active"
// ModeFull enables all modules (requires explicit consent confirmation).
ModeFull Mode = "full"
)

// Config captures runtime configuration for the site-audit tool.
type Config struct {
Mode        Mode           `json:"mode" yaml:"mode"`
Targets     []Target       `json:"targets" yaml:"targets"`
HTTP        HTTPConfig     `json:"http" yaml:"http"`
Crawler     CrawlerConfig  `json:"crawler" yaml:"crawler"`
RateLimit   RateLimit      `json:"rateLimit" yaml:"rateLimit"`
Reporting   Reporting      `json:"reporting" yaml:"reporting"`
Artifacts   ArtifactConfig `json:"artifacts" yaml:"artifacts"`
Redaction   Redaction      `json:"redaction" yaml:"redaction"`
ConsentFile string         `json:"consentFile" yaml:"consentFile"`
}

// Target defines a domain or host that can be scanned.
type Target struct {
URL          string   `json:"url" yaml:"url"`
AllowedHosts []string `json:"allowedHosts" yaml:"allowedHosts"`
MaxDepth     int      `json:"maxDepth" yaml:"maxDepth"`
ScopeFile    string   `json:"scopeFile" yaml:"scopeFile"`
}

// HTTPConfig governs HTTP request behaviour.
type HTTPConfig struct {
UserAgent      string        `json:"userAgent" yaml:"userAgent"`
Timeout        time.Duration `json:"timeout" yaml:"timeout"`
RetryMax       int           `json:"retryMax" yaml:"retryMax"`
RetryWaitMin   time.Duration `json:"retryWaitMin" yaml:"retryWaitMin"`
RetryWaitMax   time.Duration `json:"retryWaitMax" yaml:"retryWaitMax"`
RespectRobots  bool          `json:"respectRobots" yaml:"respectRobots"`
AllowInsecure  bool          `json:"allowInsecure" yaml:"allowInsecure"`
MaxConcurrency int           `json:"maxConcurrency" yaml:"maxConcurrency"`
}

// CrawlerConfig captures crawler specific settings.
type CrawlerConfig struct {
MaxDepth        int           `json:"maxDepth" yaml:"maxDepth"`
MaxPages        int           `json:"maxPages" yaml:"maxPages"`
CrawlDelay      time.Duration `json:"crawlDelay" yaml:"crawlDelay"`
FollowRedirects bool          `json:"followRedirects" yaml:"followRedirects"`
}

// RateLimit configures rate limiting for active modules.
type RateLimit struct {
RequestsPerMinute int `json:"requestsPerMinute" yaml:"requestsPerMinute"`
Burst             int `json:"burst" yaml:"burst"`
}

// Reporting handles output configuration.
type Reporting struct {
OutputDir  string `json:"outputDir" yaml:"outputDir"`
FormatJSON bool   `json:"formatJson" yaml:"formatJson"`
FormatHTML bool   `json:"formatHtml" yaml:"formatHtml"`
FormatSARIF bool  `json:"formatSarif" yaml:"formatSarif"`
}

// ArtifactConfig defines artifact collection preferences.
type ArtifactConfig struct {
EnableScreenshots bool `json:"enableScreenshots" yaml:"enableScreenshots"`
EnableHAR         bool `json:"enableHar" yaml:"enableHar"`
EnableSBOM        bool `json:"enableSbom" yaml:"enableSbom"`
}

// Redaction config toggles redaction of PII.
type Redaction struct {
RetainPII bool `json:"retainPii" yaml:"retainPii"`
}

// DefaultConfig returns a minimal safe configuration.
func DefaultConfig() Config {
return Config{
Mode: ModePassive,
HTTP: HTTPConfig{
UserAgent:      "site-audit/0.1",
Timeout:        15 * time.Second,
RetryMax:       2,
RetryWaitMin:   500 * time.Millisecond,
RetryWaitMax:   2 * time.Second,
RespectRobots:  true,
AllowInsecure:  false,
MaxConcurrency: 4,
},
Crawler: CrawlerConfig{
MaxDepth:        2,
MaxPages:        100,
CrawlDelay:      1 * time.Second,
FollowRedirects: true,
},
RateLimit: RateLimit{
RequestsPerMinute: 30,
Burst:             2,
},
Reporting: Reporting{
OutputDir:  "artifacts",
FormatJSON: true,
FormatHTML: true,
FormatSARIF: false,
},
Artifacts: ArtifactConfig{
EnableScreenshots: true,
EnableHAR:         true,
EnableSBOM:        true,
},
Redaction: Redaction{
RetainPII: false,
},
}
}

// Load reads configuration from disk. Supports JSON and YAML.
func Load(path string) (Config, error) {
cfg := DefaultConfig()
if path == "" {
return cfg, nil
}

file, err := os.Open(filepath.Clean(path))
if err != nil {
return Config{}, fmt.Errorf("open config: %w", err)
}
defer file.Close()

data, err := io.ReadAll(file)
if err != nil {
return Config{}, fmt.Errorf("read config: %w", err)
}

switch strings.ToLower(filepath.Ext(path)) {
case ".yaml", ".yml":
if err := yaml.Unmarshal(data, &cfg); err != nil {
return Config{}, fmt.Errorf("parse yaml: %w", err)
}
case ".json":
if err := json.Unmarshal(data, &cfg); err != nil {
return Config{}, fmt.Errorf("parse json: %w", err)
}
default:
if err := json.Unmarshal(data, &cfg); err != nil {
if yamlErr := yaml.Unmarshal(data, &cfg); yamlErr != nil {
return Config{}, fmt.Errorf("parse config: %v; %v", err, yamlErr)
}
}
}

return cfg, cfg.Validate()
}

// Validate ensures the configuration is safe and internally consistent.
func (c Config) Validate() error {
if len(c.Targets) == 0 {
return errors.New("at least one target must be defined")
}

if c.Mode == ModeFull || c.Mode == ModeSafeActive {
if strings.TrimSpace(c.ConsentFile) == "" {
return errors.New("consentFile must be provided for active modes")
}
}

if c.HTTP.UserAgent == "" {
return errors.New("http.userAgent must be set")
}

if c.HTTP.Timeout <= 0 {
return errors.New("http.timeout must be greater than zero")
}

if c.HTTP.MaxConcurrency <= 0 {
return errors.New("http.maxConcurrency must be greater than zero")
}

if c.RateLimit.RequestsPerMinute < 0 {
return errors.New("rateLimit.requestsPerMinute cannot be negative")
}

for i, tgt := range c.Targets {
if strings.TrimSpace(tgt.URL) == "" {
return fmt.Errorf("target %d has empty url", i)
}
if tgt.MaxDepth < 0 {
return fmt.Errorf("target %d maxDepth cannot be negative", i)
}
if len(tgt.AllowedHosts) == 0 {
return fmt.Errorf("target %d must specify allowedHosts", i)
}
}

return nil
}
