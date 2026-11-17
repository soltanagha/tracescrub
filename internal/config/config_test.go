package config

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestLoadExampleConfig(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "config.example.yaml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("expected example config to load cleanly, got: %v", err)
	}

	if cfg.Server.ListenAddr != "127.0.0.1:8443" {
		t.Fatalf("unexpected listen_addr: %s", cfg.Server.ListenAddr)
	}
	if cfg.Server.AdminAddr != "127.0.0.1:9090" {
		t.Fatalf("unexpected admin_addr: %s", cfg.Server.AdminAddr)
	}
	if cfg.Server.MaxBodyBytes != 10485760 {
		t.Fatalf("unexpected max_body_bytes: %d", cfg.Server.MaxBodyBytes)
	}
	if !cfg.Security.StrictMode || !cfg.Security.DetokenizeResponses {
		t.Fatal("expected strict_mode and detokenize_responses to be true")
	}
	if cfg.Audit.IncludeRawSecrets {
		t.Fatal("expected audit.include_raw_secrets to be false")
	}
	if len(cfg.Security.CustomRules) != 1 || cfg.Security.CustomRules[0].ID != "corp-internal-api" {
		t.Fatalf("unexpected custom rules: %+v", cfg.Security.CustomRules)
	}
	if !slices.Contains(cfg.Security.AllowlistPatterns, tokenAllowlistPattern) {
		t.Fatal("expected token allowlist pattern to be present")
	}
}

func TestConfigValidationRejectsInsecureSettings(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "include_raw_secrets_true",
			yaml: `
audit:
  enabled: true
  include_raw_secrets: true
`,
		},
		{
			name: "non_loopback_admin_addr",
			yaml: `
server:
  admin_addr: "0.0.0.0:9090"
`,
		},
		{
			name: "invalid_custom_rule_regex",
			yaml: `
security:
  custom_rules:
    - id: "bad-regex"
      pattern: "[unclosed"
`,
		},
		{
			name: "invalid_upstream_scheme",
			yaml: `
upstream:
  default_target: "ftp://example.com"
`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.yaml)); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestConfigAppliesDefaultsAndPreservesExplicitFalse(t *testing.T) {
	raw := `
security:
  strict_mode: false
  detokenize_responses: false
  allowlist_patterns:
    - "CUSTOM_SAFE"
`
	cfg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if cfg.Security.StrictMode {
		t.Fatal("expected explicit strict_mode: false to be preserved")
	}
	if cfg.Security.DetokenizeResponses {
		t.Fatal("expected explicit detokenize_responses: false to be preserved")
	}
	if !slices.Contains(cfg.Security.AllowlistPatterns, tokenAllowlistPattern) {
		t.Fatal("expected token allowlist pattern to always be injected")
	}
	if !slices.Contains(cfg.Security.AllowlistPatterns, "CUSTOM_SAFE") {
		t.Fatal("expected custom allowlist pattern to be preserved")
	}
}
