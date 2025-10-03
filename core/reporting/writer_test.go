package reporting

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CodecubeWeb3/site-audit/core/model"
)

func TestWriteJSONAndHTML(t *testing.T) {
	tmpDir := t.TempDir()
	run := &model.RunResult{
		StartedAt: time.Now(),
		Completed: time.Now(),
		Mode:      "passive",
		Targets:   []model.TargetResult{},
	}

	jsonPath := filepath.Join(tmpDir, "run.json")
	htmlPath := filepath.Join(tmpDir, "report.html")

	if err := WriteJSON(jsonPath, run); err != nil {
		t.Fatalf("write json: %v", err)
	}
	if err := WriteHTML(htmlPath, run); err != nil {
		t.Fatalf("write html: %v", err)
	}

	if _, err := os.Stat(jsonPath); err != nil {
		t.Fatalf("json missing: %v", err)
	}
	if _, err := os.Stat(htmlPath); err != nil {
		t.Fatalf("html missing: %v", err)
	}
}
