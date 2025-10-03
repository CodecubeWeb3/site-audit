package securitypassive

import (
	"regexp"
	"strings"

	"github.com/CodecubeWeb3/site-audit/modules/httpcheck"
)

var errorIndicators = []*regexp.Regexp{
	regexp.MustCompile(`(?i)index of /`),
	regexp.MustCompile(`(?i)exception in`),
	regexp.MustCompile(`(?i)fatal error`),
	regexp.MustCompile(`(?i)stack trace`),
}

// Result represents passive security hygiene findings.
type Result struct {
	ExposedHeaders []string
	ErrorPatterns  []string
	WellKnownHints []string
	CookieIssues   []string
	Findings       []string
}

// Analyze inspects HTTP response metadata and body for passive security indicators.
func Analyze(res *httpcheck.Result, body string) Result {
	out := Result{}
	headers := map[string]string{}
	if res != nil {
		headers = res.Headers
	}

	if val := headers["server"]; val != "" {
		out.ExposedHeaders = append(out.ExposedHeaders, "Server: "+val)
	}
	if val := headers["x-powered-by"]; val != "" {
		out.ExposedHeaders = append(out.ExposedHeaders, "X-Powered-By: "+val)
	}

	if cookie := headers["set-cookie"]; cookie != "" {
		cookies := strings.Split(cookie, ",")
		for _, c := range cookies {
			lower := strings.ToLower(c)
			if !strings.Contains(lower, "httponly") {
				out.CookieIssues = append(out.CookieIssues, "cookie missing HttpOnly: "+strings.TrimSpace(c))
			}
			if !strings.Contains(lower, "secure") {
				out.CookieIssues = append(out.CookieIssues, "cookie missing Secure: "+strings.TrimSpace(c))
			}
		}
	}

	for _, re := range errorIndicators {
		if re.MatchString(body) {
			out.ErrorPatterns = append(out.ErrorPatterns, re.String())
		}
	}

	if strings.Contains(body, ".well-known/security.txt") {
		out.WellKnownHints = append(out.WellKnownHints, "security.txt referenced")
	}
	if strings.Contains(body, ".well-known/apple-app-site-association") {
		out.WellKnownHints = append(out.WellKnownHints, "AASA referenced")
	}

	if len(out.ExposedHeaders) > 0 {
		out.Findings = append(out.Findings, "server technology exposure via headers")
	}
	if len(out.ErrorPatterns) > 0 {
		out.Findings = append(out.Findings, "error messages exposed in content")
	}
	if len(out.CookieIssues) > 0 {
		out.Findings = append(out.Findings, "cookies missing security attributes")
	}

	return out
}
