package dmca

import (
	"archive/zip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestCreatePackGeneratesManifest(t *testing.T) {
	tmpDir := t.TempDir()
	evidenceFile := filepath.Join(tmpDir, "page.html")
	if err := os.WriteFile(evidenceFile, []byte("<html>test</html>"), 0o600); err != nil {
		t.Fatalf("write evidence: %v", err)
	}

	packager := NewPackager(filepath.Join(tmpDir, "out"))
	archivePath, err := packager.CreatePack(context.Background(), Evidence{
		Complainant: "Example Corp",
		Infringing: []EvidenceItem{{
			Path: evidenceFile,
			Type: "html",
		}},
		Metadata: map[string]string{"case": "123"},
	})
	if err != nil {
		t.Fatalf("create pack: %v", err)
	}

	stat, err := os.Stat(archivePath)
	if err != nil {
		t.Fatalf("archive missing: %v", err)
	}
	if stat.Size() == 0 {
		t.Fatalf("archive empty")
	}

	zipReader, err := zip.OpenReader(archivePath)
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	defer zipReader.Close()

	var manifest Manifest
	foundManifest := false
	for _, f := range zipReader.File {
		if f.Name == "manifest.json" {
			foundManifest = true
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("open manifest: %v", err)
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatalf("read manifest: %v", err)
			}
			if err := json.Unmarshal(data, &manifest); err != nil {
				t.Fatalf("unmarshal manifest: %v", err)
			}
		}
	}

	if !foundManifest {
		t.Fatalf("manifest missing from archive")
	}
	if len(manifest.Items) != 1 {
		t.Fatalf("expected single manifest item")
	}
	if manifest.Items[0].LogicalPath != evidenceFile {
		t.Fatalf("unexpected manifest logical path")
	}
}
