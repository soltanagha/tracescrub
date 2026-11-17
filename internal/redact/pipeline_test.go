package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tracescrub/tracescrub/internal/audit"
	"github.com/tracescrub/tracescrub/internal/config"
	"github.com/tracescrub/tracescrub/internal/vault"
)

func newTestPipeline(t testing.TB) (*Pipeline, *vault.EphemeralVault) {
	t.Helper()
	v, err := vault.New(5 * time.Minute)
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })

	cfg := config.SecurityConfig{
		StrictMode:          true,
		DetokenizeResponses: true,
		VaultTTLSeconds:     300,
		EntropyThreshold:    4.5,
		MinEntropyLength:    20,
		AllowlistPatterns: []string{
			`^__TS_TOK_[a-f0-9]{8}__$`,
			`EXAMPLE_KEY_DO_NOT_USE`,
		},
		CustomRules: []config.CustomRuleConfig{
			{
				ID:                "corp-internal-api",
				Pattern:           `CORP_[A-Z0-9]{24}`,
				ReplacementPrefix: "CORP",
			},
		},
	}

	var auditBuf bytes.Buffer
	al := audit.NewWriter(&auditBuf)
	p, err := NewPipeline(cfg, v, al)
	if err != nil {
		t.Fatalf("create pipeline: %v", err)
	}
	return p, v
}

// QA-01: Built-in rules, custom YAML rules, nested JSON, allowlist, and zero false positives.
func TestQA01_AllSecretRulesCustomRulesAndAllowlist(t *testing.T) {
	p, v := newTestPipeline(t)

	awsKey := "AKIAIOSFODNN7EXAMPLE"
	ghPat := "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
	ghFine := "github_pat_11ABCDEFG0123456789012_abcdefghijklmnopqrstuvwxyz"
	openAIKey := "sk-proj-abc123def456ghi789jkl012mno345pqr"
	anthropicKey := "sk-ant-api03-99887766554433221100aabbccddeeff"
	fireworksKey := "fw_3Z9xLmN2pQ8rT5vW1yA4cE7gH0jK"
	pemKey := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAv7testkeymaterial1234567890\n-----END RSA PRIVATE KEY-----"
	jwtTok := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	dbURL := "postgres://dbadmin:Sup3rS3cretPass@prod-db.internal:5432/payments"
	genericSecret := "x9Kp2mQ7vR4nL8wZ3jF6cT1yB5hN0gD4a"
	corpSecret := "CORP_1234567890ABCDEFGHJKLMNP"

	payload := map[string]any{
		"model": "claude-sonnet",
		"messages": []any{
			map[string]any{
				"role": "user",
				"content": fmt.Sprintf(
					"Deploy with AWS=%s GH=%s GH2=%s OAI=%s ANT=%s FW=%s\nPEM:\n%s\nJWT=%s\nDB=%s\napi_key=%s\nORG=%s",
					awsKey, ghPat, ghFine, openAIKey, anthropicKey, fireworksKey, pemKey, jwtTok, dbURL, genericSecret, corpSecret,
				),
			},
			map[string]any{
				"role":    "assistant",
				"content": "Safe values: EXAMPLE_KEY_DO_NOT_USE and __TS_TOK_a1b2c3d4__",
			},
		},
		"metadata": map[string]any{
			"nested": []any{
				map[string]any{
					"uuid":       "550e8400-e29b-41d4-a716-446655440000",
					"commit_sha": "4a7f9c2e1b8d0f3a6c5e4d2b1a9f8e7d6c5b4a3f",
					"sha256":     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					"snippet":    "func verifyDiskQuota(ctx context.Context, taskID string) bool { return diskSpaceCheck(taskID) }",
				},
			},
		},
	}

	rawJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	scrubbed, findings, err := p.ScrubJSON("sess-qa01", rawJSON)
	if err != nil {
		t.Fatalf("ScrubJSON failed: %v", err)
	}

	scrubbedStr := string(scrubbed)
	secrets := []string{
		awsKey, ghPat, ghFine, openAIKey, anthropicKey, fireworksKey,
		pemKey, jwtTok, dbURL, genericSecret, corpSecret,
	}
	for _, s := range secrets {
		if strings.Contains(scrubbedStr, s) {
			t.Fatalf("secret %q leaked into scrubbed output: %s", s, scrubbedStr)
		}
	}

	// Verify allowlist and non-secret values remained intact.
	preserved := []string{
		"EXAMPLE_KEY_DO_NOT_USE",
		"__TS_TOK_a1b2c3d4__",
		"550e8400-e29b-41d4-a716-446655440000",
		"4a7f9c2e1b8d0f3a6c5e4d2b1a9f8e7d6c5b4a3f",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"func verifyDiskQuota(ctx context.Context, taskID string) bool { return diskSpaceCheck(taskID) }",
	}
	for _, want := range preserved {
		if !strings.Contains(scrubbedStr, want) {
			t.Fatalf("expected non-secret/allowlisted value %q to be preserved in %s", want, scrubbedStr)
		}
	}

	// Verify all findings can be de-tokenized via the vault for sess-qa01.
	if len(findings) < len(secrets) {
		t.Fatalf("expected at least %d findings, got %d", len(secrets), len(findings))
	}
	for _, f := range findings {
		if _, err := v.Resolve("sess-qa01", f.TokenID); err != nil {
			t.Fatalf("expected token %q (rule %s) to resolve in vault: %v", f.TokenID, f.RuleID, err)
		}
	}
}

// QA-02: Shannon entropy context sensitivity and zero false positives on non-keyword blobs.
func TestQA02_EntropyContextSensitivity(t *testing.T) {
	p, _ := newTestPipeline(t)

	highEntropySecret := "k9X2mP7qR4vL8nZ3jF6wT1yB5cN0hD4s"
	if h := ShannonEntropy(highEntropySecret); h < 4.5 {
		t.Fatalf("test setup error: expected entropy >= 4.5, got %.2f", h)
	}

	// Case 1: High-entropy value near context keyword must be scrubbed.
	withKeyword, _ := json.Marshal(map[string]any{
		"prompt": "Set bearer " + highEntropySecret + " on outgoing requests",
	})
	scrubbedWithKW, findingsWithKW, err := p.ScrubJSON("sess-qa02", withKeyword)
	if err != nil {
		t.Fatalf("ScrubJSON failed: %v", err)
	}
	if strings.Contains(string(scrubbedWithKW), highEntropySecret) {
		t.Fatalf("expected keyword-adjacent secret to be redacted, got: %s", scrubbedWithKW)
	}
	if len(findingsWithKW) != 1 || findingsWithKW[0].RuleID != HighEntropyRuleID {
		t.Fatalf("expected 1 high-entropy-secret finding, got: %+v", findingsWithKW)
	}

	// Case 2: High-entropy value inside JSON key named "secret" must be scrubbed.
	withKeyField, _ := json.Marshal(map[string]any{
		"client_secret": highEntropySecret,
	})
	scrubbedKeyField, findingsKeyField, err := p.ScrubJSON("sess-qa02", withKeyField)
	if err != nil {
		t.Fatalf("ScrubJSON failed: %v", err)
	}
	if strings.Contains(string(scrubbedKeyField), highEntropySecret) {
		t.Fatalf("expected secret under client_secret key to be redacted, got: %s", scrubbedKeyField)
	}
	if len(findingsKeyField) != 1 {
		t.Fatalf("expected 1 finding for client_secret, got %d", len(findingsKeyField))
	}

	// Case 3: High-entropy base64 image data / blob WITHOUT context keywords must NOT be redacted.
	base64Image := "iVBORw0KGgoAAAANSUhEUgAAAOEAAADhCAYAAAA+s9J6AAAgAElEQVR4nO29eZhc"
	withoutKeyword, _ := json.Marshal(map[string]any{
		"image_data": base64Image,
		"note":       "Compiled hash without keywords: " + highEntropySecret + " and keyboard_layout_config_value_123456",
	})
	scrubbedNoKW, findingsNoKW, err := p.ScrubJSON("sess-qa02", withoutKeyword)
	if err != nil {
		t.Fatalf("ScrubJSON failed: %v", err)
	}
	if len(findingsNoKW) != 0 {
		t.Fatalf("expected 0 false positives without context keywords, got: %+v (%s)", findingsNoKW, scrubbedNoKW)
	}
	if !strings.Contains(string(scrubbedNoKW), base64Image) || !strings.Contains(string(scrubbedNoKW), highEntropySecret) {
		t.Fatalf("expected non-keyword high-entropy payloads to remain untouched, got: %s", scrubbedNoKW)
	}

	// Case 4: Context keyword > 64 chars away from high-entropy string must NOT trigger.
	padding := strings.Repeat("a", 80)
	farKeyword, _ := json.Marshal(map[string]any{
		"prompt": "token is mentioned here " + padding + " " + highEntropySecret,
	})
	_, findingsFar, err := p.ScrubJSON("sess-qa02", farKeyword)
	if err != nil {
		t.Fatalf("ScrubJSON failed: %v", err)
	}
	if len(findingsFar) != 0 {
		t.Fatalf("expected 0 findings when keyword is > 64 chars away, got %+v", findingsFar)
	}
}

func makeBenchmarkPayload(targetBytes int) []byte {
	snippet := `package auth
import ("context"; "fmt")
// ProcessRequest handles incoming prompt context without leaking credentials.
func ProcessRequest(ctx context.Context, user string) string {
	return fmt.Sprintf("user=%s status=ok", user)
}
`
	var messages []map[string]any
	total := 0
	i := 0
	for total < targetBytes {
		content := snippet
		if i == 0 {
			content = "AWS=AKIAIOSFODNN7EXAMPLE GH=ghp_1234567890abcdefghijklmnopqrstuvwxyz\n" + snippet
		}
		messages = append(messages, map[string]any{
			"role":    "user",
			"content": content,
		})
		total += len(content) + 32
		i++
	}
	b, _ := json.Marshal(map[string]any{
		"model":    "gpt-4o",
		"messages": messages,
	})
	return b
}

// QA-09: 10 KB redaction benchmark.
func BenchmarkScrubJSON_10KB(b *testing.B) {
	p, _ := newTestPipeline(b)
	payload := makeBenchmarkPayload(10 * 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := p.ScrubJSON("bench-10k", payload); err != nil {
			b.Fatalf("ScrubJSON failed: %v", err)
		}
	}
}

// QA-09: 100 KB redaction benchmark.
func BenchmarkScrubJSON_100KB(b *testing.B) {
	p, _ := newTestPipeline(b)
	payload := makeBenchmarkPayload(100 * 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := p.ScrubJSON("bench-100k", payload); err != nil {
			b.Fatalf("ScrubJSON failed: %v", err)
		}
	}
}
