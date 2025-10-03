package dmca

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Evidence describes the artefacts bundled into a DMCA package.
type Evidence struct {
	Complainant string            `json:"complainant"`
	Infringing  []EvidenceItem    `json:"infringing"`
	Metadata    map[string]string `json:"metadata"`
}

// EvidenceItem represents a file added to the pack.
type EvidenceItem struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

// Manifest documents the packaged evidence for integrity tracking.
type Manifest struct {
	GeneratedAt time.Time         `json:"generatedAt"`
	Complainant string            `json:"complainant"`
	Items       []ManifestItem    `json:"items"`
	Metadata    map[string]string `json:"metadata"`
	Hashes      map[string]string `json:"hashes"`
	ConsentNote string            `json:"consentNote"`
}

// ManifestItem links filenames with logical evidence entries.
type ManifestItem struct {
	LogicalPath string `json:"logicalPath"`
	ArchivePath string `json:"archivePath"`
	Type        string `json:"type"`
}

// Packager writes DMCA evidence archives with manifests.
type Packager struct {
	OutputDir string
}

// NewPackager initialises a packager with a default output directory.
func NewPackager(outputDir string) *Packager {
	if outputDir == "" {
		outputDir = "artifacts/evidence"
	}
	return &Packager{OutputDir: outputDir}
}

// CreatePack creates a timestamped DMCA evidence archive.
func (p *Packager) CreatePack(ctx context.Context, ev Evidence) (string, error) {
	if len(ev.Infringing) == 0 {
		return "", fmt.Errorf("no evidence items provided")
	}

	if err := os.MkdirAll(p.OutputDir, 0o755); err != nil {
		return "", fmt.Errorf("make output dir: %w", err)
	}

	archiveName := fmt.Sprintf("dmca-pack-%s.zip", time.Now().UTC().Format("20060102-150405"))
	archivePath := filepath.Join(p.OutputDir, archiveName)

	file, err := os.Create(archivePath)
	if err != nil {
		return "", fmt.Errorf("create archive: %w", err)
	}
	defer file.Close()

	zipWriter := zip.NewWriter(file)
	defer zipWriter.Close()

	manifest := Manifest{
		GeneratedAt: time.Now().UTC(),
		Complainant: ev.Complainant,
		Metadata:    ev.Metadata,
		Hashes:      map[string]string{},
	}

	for _, item := range ev.Infringing {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		if item.Path == "" {
			continue
		}

		info, err := os.Stat(item.Path)
		if err != nil {
			return "", fmt.Errorf("stat evidence %s: %w", item.Path, err)
		}
		if info.IsDir() {
			continue
		}

		src, err := os.Open(item.Path)
		if err != nil {
			return "", fmt.Errorf("open evidence %s: %w", item.Path, err)
		}

		hash := sha256.New()
		multi := io.MultiWriter(hash)
		buf, err := io.ReadAll(src)
		src.Close()
		if err != nil {
			return "", fmt.Errorf("read evidence %s: %w", item.Path, err)
		}
		if _, err := multi.Write(buf); err != nil {
			return "", fmt.Errorf("hash evidence %s: %w", item.Path, err)
		}

		zipPath := filepath.Base(item.Path)
		writer, err := zipWriter.Create(zipPath)
		if err != nil {
			return "", fmt.Errorf("zip add %s: %w", zipPath, err)
		}
		if _, err := writer.Write(buf); err != nil {
			return "", fmt.Errorf("zip write %s: %w", zipPath, err)
		}

		manifest.Items = append(manifest.Items, ManifestItem{
			LogicalPath: item.Path,
			ArchivePath: zipPath,
			Type:        item.Type,
		})
		manifest.Hashes[item.Path] = hex.EncodeToString(hash.Sum(nil))
	}

	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal manifest: %w", err)
	}

	manifestWriter, err := zipWriter.Create("manifest.json")
	if err != nil {
		return "", fmt.Errorf("zip manifest: %w", err)
	}
	if _, err := manifestWriter.Write(manifestData); err != nil {
		return "", fmt.Errorf("write manifest: %w", err)
	}

	return archivePath, nil
}
