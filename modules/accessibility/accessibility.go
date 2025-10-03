package accessibility

import (
	"strings"

	"golang.org/x/net/html"
)

// Result summarises lightweight accessibility checks.
type Result struct {
	ImagesWithoutAlt       []string
	InputsWithoutLabel     []string
	MissingLandmarks       []string
	Issues                 []string
	DocumentLanguageAbsent bool
}

// Audit inspects an HTML document for common accessibility issues.
func Audit(body string) Result {
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

	labelFor := map[string]bool{}
	inputsInLabel := map[*html.Node]bool{}
	langPresent := false

	traverse(root, func(node *html.Node, ancestors []*html.Node) {
		if node.Type != html.ElementNode {
			return
		}
		switch strings.ToLower(node.Data) {
		case "html":
			lang := attr(node, "lang")
			if lang != "" {
				langPresent = true
			}
		case "label":
			if v := attr(node, "for"); v != "" {
				labelFor[v] = true
			}
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				if child.Type == html.ElementNode && strings.EqualFold(child.Data, "input") {
					inputsInLabel[child] = true
				}
			}
		case "img":
			alt := attr(node, "alt")
			src := attr(node, "src")
			if strings.TrimSpace(alt) == "" {
				res.ImagesWithoutAlt = append(res.ImagesWithoutAlt, src)
			}
		case "input":
			inputType := strings.ToLower(attr(node, "type"))
			if inputType == "hidden" {
				return
			}
			id := attr(node, "id")
			if labelFor[id] {
				return
			}
			if inputsInLabel[node] {
				return
			}
			if hasAncestorLabel(ancestors) {
				return
			}
			name := attr(node, "name")
			res.InputsWithoutLabel = append(res.InputsWithoutLabel, firstNonEmpty(id, name))
		case "main":
			res.MissingLandmarks = remove(res.MissingLandmarks, "main")
		case "nav":
			res.MissingLandmarks = remove(res.MissingLandmarks, "nav")
		}
	})

	requiredLandmarks := []string{"main", "nav"}
	for _, landmark := range requiredLandmarks {
		if !contains(res.MissingLandmarks, landmark) {
			res.MissingLandmarks = append(res.MissingLandmarks, landmark)
		}
	}

	if containsElement(root, "main") {
		res.MissingLandmarks = remove(res.MissingLandmarks, "main")
	}
	if containsElement(root, "nav") {
		res.MissingLandmarks = remove(res.MissingLandmarks, "nav")
	}

	if !langPresent {
		res.DocumentLanguageAbsent = true
		res.Issues = append(res.Issues, "missing lang attribute on <html>")
	}
	if len(res.ImagesWithoutAlt) > 0 {
		res.Issues = append(res.Issues, "images missing alt text")
	}
	if len(res.InputsWithoutLabel) > 0 {
		res.Issues = append(res.Issues, "form inputs missing labels")
	}
	if len(res.MissingLandmarks) > 0 {
		res.Issues = append(res.Issues, "missing landmark elements")
	}

	return res
}

func traverse(node *html.Node, fn func(*html.Node, []*html.Node)) {
	var walk func(*html.Node, []*html.Node)
	walk = func(n *html.Node, ancestors []*html.Node) {
		fn(n, ancestors)
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child, append(ancestors, n))
		}
	}
	walk(node, nil)
}

func attr(node *html.Node, name string) string {
	for _, a := range node.Attr {
		if strings.EqualFold(a.Key, name) {
			return a.Val
		}
	}
	return ""
}

func hasAncestorLabel(ancestors []*html.Node) bool {
	for _, ancestor := range ancestors {
		if ancestor.Type == html.ElementNode && strings.EqualFold(ancestor.Data, "label") {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func containsElement(node *html.Node, name string) bool {
	found := false
	traverse(node, func(n *html.Node, _ []*html.Node) {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, name) {
			found = true
		}
	})
	return found
}

func contains(slice []string, value string) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

func remove(slice []string, value string) []string {
	var out []string
	for _, v := range slice {
		if v != value {
			out = append(out, v)
		}
	}
	return out
}
