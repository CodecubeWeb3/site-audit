package accessibility

import "testing"

func TestAuditFindsCommonIssues(t *testing.T) {
	html := `<!doctype html><html><body>
<img src="/image.png">
<form><input id="email" name="email"></form>
</body></html>`
	res := Audit(html)
	if len(res.ImagesWithoutAlt) != 1 {
		t.Fatalf("expected missing alt detection, got %#v", res.ImagesWithoutAlt)
	}
	if len(res.InputsWithoutLabel) != 1 {
		t.Fatalf("expected missing label detection, got %#v", res.InputsWithoutLabel)
	}
	if len(res.Issues) == 0 {
		t.Fatal("expected reported issues")
	}
}

func TestAuditHandlesLanguageAndLandmarks(t *testing.T) {
	html := `<!doctype html><html lang="en"><body><main><nav></nav></main></body></html>`
	res := Audit(html)
	if res.DocumentLanguageAbsent {
		t.Fatal("expected language to be detected")
	}
	if len(res.MissingLandmarks) != 0 {
		t.Fatalf("expected no missing landmarks, got %#v", res.MissingLandmarks)
	}
}
