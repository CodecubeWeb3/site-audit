package config

import (
"os"
"path/filepath"
"testing"
)

func TestDefaultConfigValidationFailsWithoutTargets(t *testing.T) {
cfg := DefaultConfig()
cfg.Targets = nil
if err := cfg.Validate(); err == nil {
t.Fatalf("expected validation error for missing targets")
}
}

func TestValidationRequiresConsentForActiveModes(t *testing.T) {
cfg := DefaultConfig()
cfg.Targets = []Target{{
URL:          "https://example.com",
AllowedHosts: []string{"example.com"},
}}
cfg.Mode = ModeSafeActive
if err := cfg.Validate(); err == nil {
t.Fatalf("expected error when consent file missing for active mode")
}

cfg.ConsentFile = "consent.json"
if err := cfg.Validate(); err != nil {
t.Fatalf("unexpected error: %v", err)
}
}

func TestLoadJSON(t *testing.T) {
dir := t.TempDir()
path := filepath.Join(dir, "config.json")
data := `{
"mode": "passive",
"targets": [{"url": "https://example.com", "allowedHosts": ["example.com"]}]
}`
if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
t.Fatalf("write file: %v", err)
}

cfg, err := Load(path)
if err != nil {
t.Fatalf("load config: %v", err)
}

if len(cfg.Targets) != 1 || cfg.Targets[0].URL != "https://example.com" {
t.Fatalf("unexpected config targets: %#v", cfg.Targets)
}
}

func TestLoadYAML(t *testing.T) {
dir := t.TempDir()
path := filepath.Join(dir, "config.yaml")
data := `
mode: passive
targets:
  - url: https://example.com
    allowedHosts:
      - example.com
`
if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
t.Fatalf("write file: %v", err)
}

cfg, err := Load(path)
if err != nil {
t.Fatalf("load config: %v", err)
}

if cfg.Targets[0].URL != "https://example.com" {
t.Fatalf("unexpected URL: %s", cfg.Targets[0].URL)
}
}
