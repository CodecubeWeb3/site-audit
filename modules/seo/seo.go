package seo

import (
	"strings"

	"golang.org/x/net/html"
)

// Result captures structured SEO metadata extracted from an HTML document.
type Result struct {
	Title           string
	MetaDescription string
	Canonical       string
	Robots          string
	Hreflang        []string
	OpenGraph       map[string]string
	Twitter         map[string]string
	JSONLDSnippets  int
	Issues          []string
}

// Analyze parses the provided HTML body and extracts SEO focused metadata.
func Analyze(body string) Result {
	result := Result{
		OpenGraph: make(map[string]string),
		Twitter:   make(map[string]string),
	}
	if strings.TrimSpace(body) == "" {
		result.Issues = append(result.Issues, "empty document body")
		return result
	}

	node, err := html.Parse(strings.NewReader(body))
	if err != nil {
		result.Issues = append(result.Issues, "failed to parse html")
		return result
	}

	traverse(node, func(n *html.Node) {
		switch n.Type {
		case html.ElementNode:
			switch strings.ToLower(n.Data) {
			case "title":
				if result.Title == "" {
					result.Title = collectText(n)
				}
			case "meta":
				name := attr(n, "name")
				prop := attr(n, "property")
				content := attr(n, "content")
				switch strings.ToLower(name) {
				case "description":
					if result.MetaDescription == "" {
						result.MetaDescription = content
					}
				case "robots":
					result.Robots = content
				}
				switch strings.ToLower(prop) {
				case "og:title", "og:description", "og:url", "og:type", "og:image":
					if content != "" {
						result.OpenGraph[strings.ToLower(prop)] = content
					}
				}
				switch strings.ToLower(name) {
				case "twitter:card", "twitter:title", "twitter:description", "twitter:image":
					if content != "" {
						result.Twitter[strings.ToLower(name)] = content
					}
				}
			case "link":
				rel := strings.ToLower(attr(n, "rel"))
				href := attr(n, "href")
				if rel == "canonical" && result.Canonical == "" {
					result.Canonical = href
				}
				if rel == "alternate" {
					hreflang := attr(n, "hreflang")
					if hreflang != "" {
						result.Hreflang = append(result.Hreflang, hreflang)
					}
				}
			case "script":
				if strings.EqualFold(attr(n, "type"), "application/ld+json") {
					result.JSONLDSnippets++
				}
			}
		}
	})

	if result.Title == "" {
		result.Issues = append(result.Issues, "missing <title> tag")
	}
	if result.MetaDescription == "" {
		result.Issues = append(result.Issues, "missing meta description")
	}
	if result.Canonical == "" {
		result.Issues = append(result.Issues, "missing canonical link")
	}

	return result
}

func traverse(node *html.Node, fn func(*html.Node)) {
	fn(node)
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		traverse(child, fn)
	}
}

func collectText(node *html.Node) string {
	if node == nil {
		return ""
	}
	switch node.Type {
	case html.TextNode:
		return strings.TrimSpace(node.Data)
	}
	var sb strings.Builder
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		text := collectText(child)
		if text != "" {
			if sb.Len() > 0 {
				sb.WriteByte(' ')
			}
			sb.WriteString(text)
		}
	}
	return strings.TrimSpace(sb.String())
}

func attr(node *html.Node, name string) string {
	for _, a := range node.Attr {
		if strings.EqualFold(a.Key, name) {
			return a.Val
		}
	}
	return ""
}
