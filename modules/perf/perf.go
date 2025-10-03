package perf

import (
	"strings"

	"golang.org/x/net/html"
)

// Result summarises lightweight performance heuristics.
type Result struct {
	RenderBlockingResources []string
	ScriptCount             int
	StylesheetCount         int
	InlineStyleBytes        int
	InlineScriptBytes       int
	Issues                  []string
}

// Analyze performs static heuristics that highlight potential performance concerns.
func Analyze(body string) Result {
	res := Result{}
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
		switch strings.ToLower(node.Data) {
		case "script":
			if attr(node, "src") != "" {
				res.ScriptCount++
				if attr(node, "async") == "" && attr(node, "defer") == "" {
					res.RenderBlockingResources = append(res.RenderBlockingResources, attr(node, "src"))
				}
			} else {
				res.InlineScriptBytes += len(collectText(node))
			}
		case "link":
			if strings.EqualFold(attr(node, "rel"), "stylesheet") {
				res.StylesheetCount++
				href := attr(node, "href")
				if href != "" && attr(node, "media") == "" {
					res.RenderBlockingResources = append(res.RenderBlockingResources, href)
				}
			}
		case "style":
			res.InlineStyleBytes += len(collectText(node))
		}
	})

	if len(res.RenderBlockingResources) > 4 {
		res.Issues = append(res.Issues, "many render blocking resources detected")
	}
	if res.InlineStyleBytes > 4096 {
		res.Issues = append(res.Issues, "large inline styles detected")
	}
	if res.InlineScriptBytes > 4096 {
		res.Issues = append(res.Issues, "large inline scripts detected")
	}

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

func collectText(node *html.Node) string {
	var sb strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			sb.WriteString(n.Data)
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(node)
	return sb.String()
}
