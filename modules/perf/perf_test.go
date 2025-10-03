package perf

import "testing"

func TestAnalyzeCountsResources(t *testing.T) {
	html := `<!doctype html><html><head>
<link rel="stylesheet" href="/style.css">
<style>body{color:#000}</style>
<script src="/app.js"></script>
<script>console.log('inline')</script>
</head><body></body></html>`
	res := Analyze(html)
	if res.ScriptCount != 1 {
		t.Fatalf("expected 1 external script, got %d", res.ScriptCount)
	}
	if res.StylesheetCount != 1 {
		t.Fatalf("expected 1 stylesheet, got %d", res.StylesheetCount)
	}
	if res.InlineScriptBytes == 0 {
		t.Fatal("expected inline script bytes to be counted")
	}
	if res.InlineStyleBytes == 0 {
		t.Fatal("expected inline style bytes to be counted")
	}
}
