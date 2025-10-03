package reporting

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodecubeWeb3/site-audit/core/model"
)

// WriteJSON serialises run results to disk in JSON format.
func WriteJSON(path string, result *model.RunResult) error {
	if result == nil {
		return fmt.Errorf("result is nil")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create json: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// WriteHTML renders a lightweight HTML summary of run results.
func WriteHTML(path string, result *model.RunResult) error {
	if result == nil {
		return fmt.Errorf("result is nil")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	tpl := template.Must(template.New("report").Funcs(template.FuncMap{
		"join": func(values []string, sep string) string {
			return strings.Join(values, sep)
		},
	}).Parse(htmlTemplate))
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create html: %w", err)
	}
	defer file.Close()

	return tpl.Execute(file, result)
}

const htmlTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>site-audit report</title>
<style>
body { font-family: Arial, sans-serif; margin: 2rem; }
section { margin-bottom: 2rem; }
header { border-bottom: 1px solid #ccc; margin-bottom: 1rem; }
pre { background: #f4f4f4; padding: 1rem; overflow-x: auto; }
</style>
</head>
<body>
<header>
<h1>Site Audit Report</h1>
<p>Mode: {{.Mode}} | Started: {{.StartedAt}} | Completed: {{.Completed}}</p>
</header>
{{range .Targets}}
<section>
<h2>{{.Target.URL}}</h2>
<p>Errors: {{if .Errors}}{{range .Errors}}<br>{{.}}{{end}}{{else}}None{{end}}</p>
<h3>Security Headers Missing</h3>
<ul>
{{range .HTTP.MissingSecurity}}<li>{{.}}</li>{{else}}<li>All required headers present</li>{{end}}
</ul>
<h3>TLS Summary</h3>
<p>Version: {{if .TLS}}{{.TLS.Version}}{{else}}N/A{{end}} | Cipher: {{if .TLS}}{{.TLS.CipherSuite}}{{else}}N/A{{end}}</p>
<h3>DNS Summary</h3>
<p>A records: {{if .DNS}}{{join .DNS.A ", "}}{{else}}N/A{{end}}</p>
<h3>Fingerprint</h3>
<p>Frameworks: {{join .Fingerprint.JavaScriptFramework ", "}}</p>
<h3>SEO</h3>
{{if .SEO}}
<p>Title: {{.SEO.Title}} | Description: {{.SEO.MetaDescription}}</p>
<p>Canonical: {{.SEO.Canonical}} | Hreflang: {{join .SEO.Hreflang ", "}}</p>
<p>Issues: {{if .SEO.Issues}}{{join .SEO.Issues "; "}}{{else}}None{{end}}</p>
{{else}}<p>No SEO data</p>{{end}}
<h3>Accessibility</h3>
{{if .Accessibility}}
<p>Images missing alt: {{len .Accessibility.ImagesWithoutAlt}} | Inputs without labels: {{len .Accessibility.InputsWithoutLabel}}</p>
<p>Issues: {{if .Accessibility.Issues}}{{join .Accessibility.Issues "; "}}{{else}}None{{end}}</p>
{{else}}<p>No accessibility data</p>{{end}}
<h3>Assets</h3>
{{if .Assets}}
<p>Total assets: {{len .Assets.Assets}} | First-party: {{.Assets.FirstPartyCount}} | Third-party: {{.Assets.ThirdPartyCount}}</p>
{{else}}<p>No asset inventory</p>{{end}}
<h3>Performance Heuristics</h3>
{{if .Performance}}
<p>Render-blocking resources: {{len .Performance.RenderBlockingResources}}</p>
<p>Issues: {{if .Performance.Issues}}{{join .Performance.Issues "; "}}{{else}}None{{end}}</p>
{{else}}<p>No performance data</p>{{end}}
<h3>Security Hygiene</h3>
{{if .Security}}
<p>Exposed headers: {{len .Security.ExposedHeaders}} | Cookie issues: {{len .Security.CookieIssues}}</p>
<p>Findings: {{if .Security.Findings}}{{join .Security.Findings "; "}}{{else}}None{{end}}</p>
{{else}}<p>No security hygiene data</p>{{end}}
</section>
{{end}}
</body>
</html>`
