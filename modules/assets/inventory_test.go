package assets

import "testing"

func TestInventoryClassifiesAssets(t *testing.T) {
	html := `<!doctype html><html><head>
<link rel="stylesheet" href="/style.css">
<link rel="preload" href="https://cdn.example.com/font.woff2" as="font">
</head><body>
<img src="/image.png">
<script src="https://cdn.example.com/app.js"></script>
</body></html>`
	res := Inventory("https://example.com", html)
	if len(res.Assets) != 4 {
		t.Fatalf("expected 4 assets, got %d", len(res.Assets))
	}
	if res.FirstPartyCount != 2 {
		t.Fatalf("expected 2 first-party assets, got %d", res.FirstPartyCount)
	}
	if res.ThirdPartyCount != 2 {
		t.Fatalf("expected 2 third-party assets, got %d", res.ThirdPartyCount)
	}
}
