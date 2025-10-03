package seo

import "testing"

func TestAnalyzeExtractsMetadata(t *testing.T) {
	html := `<!doctype html><html><head><title>Example</title>
<meta name="description" content="Desc">
<meta name="robots" content="index,follow">
<meta property="og:title" content="OG Title">
<meta name="twitter:card" content="summary_large_image">
<link rel="canonical" href="https://example.com/">
<link rel="alternate" hreflang="en" href="https://example.com/en">
<script type="application/ld+json">{}</script>
</head><body></body></html>`

	res := Analyze(html)
	if res.Title != "Example" {
		t.Fatalf("expected title, got %q", res.Title)
	}
	if res.MetaDescription != "Desc" {
		t.Fatalf("expected description, got %q", res.MetaDescription)
	}
	if res.Canonical != "https://example.com/" {
		t.Fatalf("expected canonical, got %q", res.Canonical)
	}
	if len(res.Hreflang) != 1 || res.Hreflang[0] != "en" {
		t.Fatalf("expected hreflang en, got %#v", res.Hreflang)
	}
	if res.JSONLDSnippets != 1 {
		t.Fatalf("expected 1 json-ld, got %d", res.JSONLDSnippets)
	}
	if len(res.Issues) != 0 {
		t.Fatalf("expected no issues, got %#v", res.Issues)
	}
}

func TestAnalyzeReportsMissingElements(t *testing.T) {
	res := Analyze("<html><body></body></html>")
	if len(res.Issues) == 0 {
		t.Fatal("expected issues for missing tags")
	}
}
