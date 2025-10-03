package assets

import (
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// Asset describes a discovered resource reference.
type Asset struct {
	URL        string
	Type       string
	ThirdParty bool
}

// Result summarises asset inventory findings.
type Result struct {
	Assets          []Asset
	FirstPartyCount int
	ThirdPartyCount int
	Issues          []string
}

// Inventory extracts asset references from an HTML document relative to the provided base URL.
func Inventory(base string, body string) Result {
	res := Result{}
	parsedBase, _ := url.Parse(base)
	if strings.TrimSpace(body) == "" {
		res.Issues = append(res.Issues, "empty document body")
		return res
	}

	root, err := html.Parse(strings.NewReader(body))
	if err != nil {
		res.Issues = append(res.Issues, "failed to parse html")
		return res
	}

	traverse(root, func(node *html.Node) {
		if node.Type != html.ElementNode {
			return
		}
		var link string
		var assetType string
		switch strings.ToLower(node.Data) {
		case "img":
			link = attr(node, "src")
			assetType = "image"
		case "script":
			link = attr(node, "src")
			assetType = "script"
		case "link":
			rel := strings.ToLower(attr(node, "rel"))
			if rel == "stylesheet" || rel == "preload" {
				link = attr(node, "href")
				if rel == "preload" {
					assetType = strings.ToLower(attr(node, "as"))
					if assetType == "" {
						assetType = "preload"
					}
				} else {
					assetType = "stylesheet"
				}
			}
		case "video", "audio", "source":
			link = attr(node, "src")
			assetType = strings.ToLower(node.Data)
		}

		if strings.TrimSpace(link) == "" {
			return
		}

		normalized := resolveURL(parsedBase, link)
		if normalized == "" {
			res.Issues = append(res.Issues, "failed to resolve asset URL")
			return
		}

		thirdParty := isThirdParty(parsedBase, normalized)
		res.Assets = append(res.Assets, Asset{URL: normalized, Type: assetType, ThirdParty: thirdParty})
		if thirdParty {
			res.ThirdPartyCount++
		} else {
			res.FirstPartyCount++
		}
	})

	return res
}

func traverse(node *html.Node, fn func(*html.Node)) {
	fn(node)
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		traverse(child, fn)
	}
}

func attr(node *html.Node, name string) string {
	for _, a := range node.Attr {
		if strings.EqualFold(a.Key, name) {
			return a.Val
		}
	}
	return ""
}

func resolveURL(base *url.URL, href string) string {
	href = strings.TrimSpace(href)
	if href == "" {
		return ""
	}
	if base == nil {
		return href
	}
	parsed, err := url.Parse(href)
	if err != nil {
		return ""
	}
	return base.ResolveReference(parsed).String()
}

func isThirdParty(base *url.URL, raw string) bool {
	if base == nil {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if parsed.Hostname() == "" {
		return false
	}
	return !strings.EqualFold(parsed.Hostname(), base.Hostname())
}
