package fingerprint

import (
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// Result captures passive technology fingerprinting signals.
type Result struct {
	Server              string
	PoweredBy           []string
	Technologies        []string
	JavaScriptFramework []string
	CMSHints            []string
	SPARouter           string
	SourceMaps          []string
}

var (
	reReact     = regexp.MustCompile(`react`)
	reAngular   = regexp.MustCompile(`angular`)
	reVue       = regexp.MustCompile(`vue(\.js)?`)
	reSvelte    = regexp.MustCompile(`svelte`)
	reNext      = regexp.MustCompile(`__NEXT_DATA__`)
	reNuxt      = regexp.MustCompile(`__NUXT__`)
	reWordPress = regexp.MustCompile(`wp-content|wp-includes`)
	reDrupal    = regexp.MustCompile(`drupal-settings-json`)
	reJoomla    = regexp.MustCompile(`joomla`)
	reRouter    = regexp.MustCompile(`router-link|ng-view|data-route`)
	reSourceMap = regexp.MustCompile(`src=\"([^\"]+\.map)\"`)
)

// Analyze inspects headers and HTML content to infer technology signals.
func Analyze(headers http.Header, body string) Result {
	res := Result{}
	if headers != nil {
		res.Server = headers.Get("Server")
		if powered := headers.Values("X-Powered-By"); len(powered) > 0 {
			res.PoweredBy = append(res.PoweredBy, powered...)
		}
		if headers.Get("X-AspNet-Version") != "" {
			res.Technologies = append(res.Technologies, ".NET")
		}
	}

	bodyLower := strings.ToLower(body)
	if reReact.MatchString(bodyLower) {
		res.JavaScriptFramework = append(res.JavaScriptFramework, "React")
	}
	if reAngular.MatchString(bodyLower) {
		res.JavaScriptFramework = append(res.JavaScriptFramework, "Angular")
	}
	if reVue.MatchString(bodyLower) {
		res.JavaScriptFramework = append(res.JavaScriptFramework, "Vue")
	}
	if reSvelte.MatchString(bodyLower) {
		res.JavaScriptFramework = append(res.JavaScriptFramework, "Svelte")
	}
	if reNext.MatchString(body) {
		res.Technologies = append(res.Technologies, "Next.js")
	}
	if reNuxt.MatchString(body) {
		res.Technologies = append(res.Technologies, "Nuxt.js")
	}
	if reWordPress.MatchString(bodyLower) {
		res.CMSHints = append(res.CMSHints, "WordPress")
	}
	if reDrupal.MatchString(bodyLower) {
		res.CMSHints = append(res.CMSHints, "Drupal")
	}
	if reJoomla.MatchString(bodyLower) {
		res.CMSHints = append(res.CMSHints, "Joomla")
	}
	if matches := reRouter.FindStringSubmatch(bodyLower); len(matches) > 0 {
		res.SPARouter = "detected"
	}

	mapMatches := reSourceMap.FindAllStringSubmatch(body, -1)
	for _, m := range mapMatches {
		if len(m) > 1 {
			res.SourceMaps = append(res.SourceMaps, m[1])
		}
	}

	res.Technologies = dedupe(res.Technologies)
	res.PoweredBy = dedupe(res.PoweredBy)
	res.JavaScriptFramework = dedupe(res.JavaScriptFramework)
	res.CMSHints = dedupe(res.CMSHints)
	res.SourceMaps = dedupe(res.SourceMaps)

	return res
}

func dedupe(values []string) []string {
	seen := map[string]struct{}{}
	var result []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		result = append(result, v)
	}
	sort.Strings(result)
	return result
}
