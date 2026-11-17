package e2e

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tracescrub/tracescrub/internal/audit"
	"github.com/tracescrub/tracescrub/internal/config"
	"github.com/tracescrub/tracescrub/internal/extpin"
	"github.com/tracescrub/tracescrub/internal/proxy"
	"github.com/tracescrub/tracescrub/internal/redact"
	"github.com/tracescrub/tracescrub/internal/vault"
)

type seededSecrets struct {
	AWSKey       string
	GitHubPAT    string
	OpenAIKey    string
	AnthropicKey string
	FireworksKey string
	JWTToken     string
	DBURL        string
	GenericKey   string
}

func testSecrets() seededSecrets {
	return seededSecrets{
		AWSKey:       "AKIAIOSFODNN7EXAMPLE",
		GitHubPAT:    "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
		OpenAIKey:    "sk-proj-e2eOpenAITestSecret998877665544",
		AnthropicKey: "sk-ant-api03-e2eAnthropicTestSecret11223344",
		FireworksKey: "fw_3Z9xLmN2pQ8rT5vW1yA4cE7gH0jK",
		JWTToken:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRyYWNlU2NydWIifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		DBURL:        "postgres://admin:S3cr3tPassw0rd@db.internal:5432/tracescrub",
		GenericKey:   "k9X2mP7qR4vL8nZ3jF6wT1yB5cN0hD4s",
	}
}

func (s seededSecrets) all() []string {
	return []string{
		s.AWSKey,
		s.GitHubPAT,
		s.OpenAIKey,
		s.AnthropicKey,
		s.FireworksKey,
		s.JWTToken,
		s.DBURL,
		s.GenericKey,
	}
}

type e2eEnv struct {
	mockUpstream *MockLLMServer
	proxySrv     *httptest.Server
	adminSrv     *httptest.Server
	server       *proxy.Server
	vault        *vault.EphemeralVault
	auditPath    string
	auditLogger  *audit.Logger
}

func setupE2E(t *testing.T, maxBodyBytes int64) *e2eEnv {
	t.Helper()

	mock := NewMockLLMServer()
	t.Cleanup(mock.Close)

	auditPath := filepath.Join(t.TempDir(), "tracescrub-audit.jsonl")
	auditLogger, err := audit.New(true, auditPath)
	if err != nil {
		t.Fatalf("create audit logger: %v", err)
	}
	t.Cleanup(func() { _ = auditLogger.Close() })

	cfg := config.Default()
	cfg.Server.MaxBodyBytes = maxBodyBytes
	cfg.Upstream.DefaultTarget = mock.URL()
	cfg.Upstream.Routes = map[string]string{
		"/v1/messages": mock.URL(),
		"/inference/":  mock.URL(),
	}
	cfg.Audit.Enabled = true
	cfg.Audit.OutputPath = auditPath

	v, err := vault.New(cfg.VaultTTL())
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })

	pipeline, err := redact.NewPipeline(cfg.Security, v, auditLogger)
	if err != nil {
		t.Fatalf("create pipeline: %v", err)
	}

	srv, err := proxy.NewServer(cfg, v, pipeline, auditLogger)
	if err != nil {
		t.Fatalf("create proxy server: %v", err)
	}

	proxyHTTP := httptest.NewServer(srv.ProxyHandler())
	t.Cleanup(proxyHTTP.Close)

	adminHTTP := httptest.NewServer(srv.AdminHandler())
	t.Cleanup(adminHTTP.Close)

	return &e2eEnv{
		mockUpstream: mock,
		proxySrv:     proxyHTTP,
		adminSrv:     adminHTTP,
		server:       srv,
		vault:        v,
		auditPath:    auditPath,
		auditLogger:  auditLogger,
	}
}

// QA-05 + QA-06 + QA-07 + QA-08: Full end-to-end proxy, fail-closed, extpin CLI, and audit hygiene verification.
func TestQA05_06_07_08_EndToEnd(t *testing.T) {
	env := setupE2E(t, 1024*1024)
	secrets := testSecrets()

	// QA-05: Proxy redaction + de-tokenization (OpenAI JSON, OpenAI SSE, Anthropic JSON, Anthropic SSE).
	t.Run("QA-05_ZeroRawSecretsUpstreamAndFullDetokenization", func(t *testing.T) {
		prompt := fmt.Sprintf(
			"AWS=%s GH=%s OAI=%s ANT=%s FW=%s JWT=%s DB=%s api_key=%s",
			secrets.AWSKey, secrets.GitHubPAT, secrets.OpenAIKey, secrets.AnthropicKey,
			secrets.FireworksKey, secrets.JWTToken, secrets.DBURL, secrets.GenericKey,
		)

		endpoints := []struct {
			name   string
			path   string
			stream bool
		}{
			{"openai_json", "/v1/chat/completions", false},
			{"openai_sse", "/v1/chat/completions", true},
			{"anthropic_json", "/v1/messages", false},
			{"anthropic_sse", "/v1/messages", true},
		}

		for _, ep := range endpoints {
			t.Run(ep.name, func(t *testing.T) {
				reqBody, _ := json.Marshal(map[string]any{
					"model":  "claude-sonnet",
					"stream": ep.stream,
					"messages": []map[string]string{
						{"role": "user", "content": prompt},
					},
				})

				req, err := http.NewRequest(http.MethodPost, env.proxySrv.URL+ep.path, bytes.NewReader(reqBody))
				if err != nil {
					t.Fatalf("new request: %v", err)
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-TraceScrub-Session", "e2e-session-"+ep.name)

				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatalf("proxy request failed: %v", err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("unexpected status %d", resp.StatusCode)
				}

				respBytes, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("read proxy response: %v", err)
				}
				respStr := string(respBytes)

				// Client must receive 100% de-tokenized secrets back.
				for _, secret := range secrets.all() {
					if !strings.Contains(respStr, secret) {
						t.Fatalf("%s: expected de-tokenized secret %q in client response: %s", ep.name, secret, respStr)
					}
				}
			})
		}

		// Mock upstream server must have received 0 raw secret characters.
		recorded := env.mockUpstream.RecordedRequests()
		if len(recorded) != 4 {
			t.Fatalf("expected 4 upstream requests, got %d", len(recorded))
		}
		for _, rec := range recorded {
			for _, secret := range secrets.all() {
				if strings.Contains(rec.Body, secret) {
					t.Fatalf("CRITICAL LEAK: raw secret %q reached mock upstream (%s): %s", secret, rec.Path, rec.Body)
				}
			}
		}
	})

	// QA-06: Fail-closed enforcement on oversized body, malformed JSON, and vault failure.
	t.Run("QA-06_FailClosedSecurityEnforcement", func(t *testing.T) {
		smallEnv := setupE2E(t, 256)

		// 1. Oversized body (> max_body_bytes) -> 413
		oversized := strings.Repeat("X", 512)
		resp1, err := http.Post(smallEnv.proxySrv.URL+"/v1/chat/completions", "application/json", strings.NewReader(oversized))
		if err != nil {
			t.Fatalf("oversized request failed: %v", err)
		}
		resp1.Body.Close()
		if resp1.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("expected 413 for oversized body, got %d", resp1.StatusCode)
		}

		// 2. Malformed JSON with strict_mode: true -> 403
		resp2, err := http.Post(smallEnv.proxySrv.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"messages": [unclosed`))
		if err != nil {
			t.Fatalf("malformed json request failed: %v", err)
		}
		resp2.Body.Close()
		if resp2.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 for malformed JSON in strict_mode, got %d", resp2.StatusCode)
		}

		// 3. Vault failure simulation -> 502
		smallEnv.vault.SetSimulateFailure(true)
		resp3, err := http.Post(smallEnv.proxySrv.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"msg":"AKIAIOSFODNN7EXAMPLE"}`))
		if err != nil {
			t.Fatalf("vault failure request failed: %v", err)
		}
		resp3.Body.Close()
		smallEnv.vault.SetSimulateFailure(false)
		if resp3.StatusCode != http.StatusBadGateway {
			t.Fatalf("expected 502 on vault failure, got %d", resp3.StatusCode)
		}

		if got := len(smallEnv.mockUpstream.RecordedRequests()); got != 0 {
			t.Fatalf("expected 0 requests forwarded upstream on fail-closed errors, got %d", got)
		}
	})

	// QA-07: Build real CLI binary and test tracescrub ext verify end-to-end.
	t.Run("QA-07_ExtensionPinningCLIEndToEnd", func(t *testing.T) {
		tmpDir := t.TempDir()
		binPath := filepath.Join(tmpDir, "tracescrub")

		buildCmd := exec.Command("go", "build", "-o", binPath, "../../cmd/tracescrub")
		if out, err := buildCmd.CombinedOutput(); err != nil {
			t.Fatalf("failed to build CLI binary: %v\n%s", err, string(out))
		}

		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate keypair: %v", err)
		}

		validBytes := []byte("vsix-archive-claude-code-2.1.314-authentic")
		validSum := sha256.Sum256(validBytes)
		revokedBytes := []byte("vsix-archive-claude-code-2.1.312-revoked")
		revokedSum := sha256.Sum256(revokedBytes)

		policy := &extpin.TrustPolicy{
			Version:          "1",
			RequireSignature: true,
			Publishers: map[string]extpin.PublisherTrust{
				"anthropic": {
					Ed25519PublicKeyHex: hex.EncodeToString(pub),
					AllowedExtensions:   []string{"anthropic.claude-code"},
				},
			},
			PinnedArtifacts: map[string]extpin.PinnedArtifact{
				"anthropic.claude-code": {
					MinVersion:      "2.1.314",
					RevokedVersions: []string{"2.1.312", "2.1.313"},
					SHA256ByVersion: map[string]string{
						"2.1.312": hex.EncodeToString(revokedSum[:]),
						"2.1.314": hex.EncodeToString(validSum[:]),
					},
				},
			},
		}
		policyPath := filepath.Join(tmpDir, "trust-policy.json")
		if err := extpin.SavePolicy(policyPath, policy); err != nil {
			t.Fatalf("save policy: %v", err)
		}

		validFile := filepath.Join(tmpDir, "valid.vsix")
		_ = os.WriteFile(validFile, validBytes, 0o600)
		validSig := ed25519.Sign(priv, validBytes)
		_ = os.WriteFile(validFile+".sig", []byte(hex.EncodeToString(validSig)), 0o600)

		revokedFile := filepath.Join(tmpDir, "revoked.vsix")
		_ = os.WriteFile(revokedFile, revokedBytes, 0o600)
		revokedSig := ed25519.Sign(priv, revokedBytes)
		_ = os.WriteFile(revokedFile+".sig", []byte(hex.EncodeToString(revokedSig)), 0o600)

		tamperedFile := filepath.Join(tmpDir, "tampered.vsix")
		tamperedBytes := append([]byte(nil), validBytes...)
		tamperedBytes[0] ^= 0xFF
		_ = os.WriteFile(tamperedFile, tamperedBytes, 0o600)
		_ = os.WriteFile(tamperedFile+".sig", []byte(hex.EncodeToString(validSig)), 0o600)

		badSigFile := filepath.Join(tmpDir, "badsig.vsix")
		_ = os.WriteFile(badSigFile, validBytes, 0o600)
		_, badPriv, _ := ed25519.GenerateKey(rand.Reader)
		badSig := ed25519.Sign(badPriv, validBytes)
		_ = os.WriteFile(badSigFile+".sig", []byte(hex.EncodeToString(badSig)), 0o600)

		runVerify := func(file, ver string) (int, extpin.VerifyResult) {
			cmd := exec.Command(
				binPath, "ext", "verify",
				"--file", file,
				"--publisher", "anthropic",
				"--version", ver,
				"--policy", policyPath,
				"--audit-log", env.auditPath,
			)
			out, err := cmd.CombinedOutput()
			exitCode := 0
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					exitCode = exitErr.ExitCode()
				} else {
					t.Fatalf("exec failed unexpectedly: %v", err)
				}
			}
			var res extpin.VerifyResult
			if jsonErr := json.Unmarshal(out, &res); jsonErr != nil {
				t.Fatalf("failed to parse CLI JSON output (%v): %s", jsonErr, string(out))
			}
			return exitCode, res
		}

		if code, res := runVerify(validFile, "2.1.314"); code != 0 || !res.Allowed {
			t.Fatalf("(a) expected exit 0 and allowed=true, got exit=%d res=%+v", code, res)
		}
		if code, res := runVerify(revokedFile, "2.1.312"); code == 0 || res.Allowed || res.ViolationCode != "version_revoked" {
			t.Fatalf("(b) expected non-zero and version_revoked, got exit=%d res=%+v", code, res)
		}
		if code, res := runVerify(tamperedFile, "2.1.314"); code == 0 || res.Allowed || res.ViolationCode != "sha256_mismatch" {
			t.Fatalf("(c) expected non-zero and sha256_mismatch, got exit=%d res=%+v", code, res)
		}
		if code, res := runVerify(badSigFile, "2.1.314"); code == 0 || res.Allowed || res.ViolationCode != "invalid_signature" {
			t.Fatalf("(d) expected non-zero and invalid_signature, got exit=%d res=%+v", code, res)
		}
	})

	// QA-08: Inspect generated tracescrub-audit.jsonl for hashes, rule IDs, timestamps, and 0 raw secrets.
	t.Run("QA-08_AuditLogZeroSecretsHygiene", func(t *testing.T) {
		_ = env.auditLogger.Close()

		auditBytes, err := os.ReadFile(env.auditPath)
		if err != nil {
			t.Fatalf("read audit log: %v", err)
		}
		auditText := string(auditBytes)
		if strings.TrimSpace(auditText) == "" {
			t.Fatal("expected non-empty audit log")
		}

		// Must contain 0 occurrences of any seeded raw secret.
		for _, secret := range secrets.all() {
			if strings.Contains(auditText, secret) {
				t.Fatalf("CRITICAL AUDIT LEAK: raw secret %q found in %s", secret, env.auditPath)
			}
		}

		// Every line must be valid JSON with required metadata and SHA-256 digests.
		var sawProxyRedaction, sawExtPin bool
		scanner := bufio.NewScanner(strings.NewReader(auditText))
		for scanner.Scan() {
			line := scanner.Text()
			var rec map[string]any
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatalf("invalid audit JSONL line: %v (%s)", err, line)
			}
			for _, field := range []string{"timestamp", "rule_id", "rule_id_sha256", "event_hash_sha256", "event_type"} {
				v, ok := rec[field].(string)
				if !ok || v == "" {
					t.Fatalf("missing audit field %q in line %s", field, line)
				}
			}
			if rec["event_type"] == "secret_redacted" {
				sawProxyRedaction = true
			}
			if rec["event_type"] == "extension_verify" {
				sawExtPin = true
			}
		}
		if !sawProxyRedaction || !sawExtPin {
			t.Fatalf("expected both secret_redacted (%v) and extension_verify (%v) events in audit log", sawProxyRedaction, sawExtPin)
		}
	})

	// Verify /metrics on admin endpoint reflects proxy activity.
	t.Run("AdminMetricsVerification", func(t *testing.T) {
		resp, err := http.Get(env.adminSrv.URL + "/metrics")
		if err != nil {
			t.Fatalf("get metrics: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		metricsText := string(body)
		for _, metric := range []string{
			"tracescrub_requests_total",
			"tracescrub_secrets_redacted_total",
			"tracescrub_redaction_latency_ms",
			"tracescrub_blocked_requests_total",
		} {
			if !strings.Contains(metricsText, metric) {
				t.Fatalf("expected metric %q in /metrics output:\n%s", metric, metricsText)
			}
		}
	})
}

// QA-09: Verify p99 proxy + redaction latency meets < 5 ms (10 KB) and < 25 ms (100 KB).
func TestQA09_ProxyLatencySLO(t *testing.T) {
	env := setupE2E(t, 10*1024*1024)

	buildPayload := func(targetBytes int) []byte {
		codeBlock := `func authenticateRequest(ctx context.Context, cfg *Config) error { return cfg.VerifySession(ctx) }`
		var msgs []map[string]string
		total := 0
		for i := 0; total < targetBytes; i++ {
			c := codeBlock
			if i == 0 {
				c = "AWS=AKIAIOSFODNN7EXAMPLE " + codeBlock
			}
			msgs = append(msgs, map[string]string{"role": "user", "content": c})
			total += len(c) + 25
		}
		b, _ := json.Marshal(map[string]any{"model": "gpt-4o", "messages": msgs})
		return b
	}

	measureP99 := func(payload []byte, iterations int) time.Duration {
		// Warm up connection pool and JIT/caches.
		for w := 0; w < 5; w++ {
			req, _ := http.NewRequest(http.MethodPost, env.proxySrv.URL+"/v1/chat/completions", bytes.NewReader(payload))
			req.Header.Set("X-TraceScrub-Session", "perf-warmup")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("warmup failed: %v", err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}

		latencies := make([]time.Duration, 0, iterations)
		for i := 0; i < iterations; i++ {
			start := time.Now()
			req, _ := http.NewRequest(http.MethodPost, env.proxySrv.URL+"/v1/chat/completions", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-TraceScrub-Session", "perf-session")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("perf request failed: %v", err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			latencies = append(latencies, time.Since(start))
		}
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		idx99 := int(float64(len(latencies))*0.99) - 1
		if idx99 < 0 {
			idx99 = 0
		}
		return latencies[idx99]
	}

	p99_10k := measureP99(buildPayload(10*1024), 50)
	t.Logf("10 KB proxy+redaction p99 latency: %v", p99_10k)
	if p99_10k >= 5*time.Millisecond {
		t.Fatalf("10 KB p99 latency %v exceeded 5ms SLO", p99_10k)
	}

	p99_100k := measureP99(buildPayload(100*1024), 30)
	t.Logf("100 KB proxy+redaction p99 latency: %v", p99_100k)
	if p99_100k >= 25*time.Millisecond {
		t.Fatalf("100 KB p99 latency %v exceeded 25ms SLO", p99_100k)
	}
}
