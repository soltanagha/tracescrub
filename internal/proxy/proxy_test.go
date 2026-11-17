package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tracescrub/tracescrub/internal/audit"
	"github.com/tracescrub/tracescrub/internal/config"
	"github.com/tracescrub/tracescrub/internal/redact"
	"github.com/tracescrub/tracescrub/internal/vault"
)

type chunkedReader struct {
	chunks [][]byte
	idx    int
	offset int
}

func (c *chunkedReader) Read(p []byte) (int, error) {
	for c.idx < len(c.chunks) {
		cur := c.chunks[c.idx]
		if c.offset >= len(cur) {
			c.idx++
			c.offset = 0
			continue
		}
		n := copy(p, cur[c.offset:])
		c.offset += n
		return n, nil
	}
	return 0, io.EOF
}

func (c *chunkedReader) Close() error { return nil }

// QA-04: Verify StreamDeTokenizer seamlessly reconstructs split tokens across 1-byte, 7-byte, and 64-byte chunks.
func TestQA04_StreamDeTokenizerSplitChunks(t *testing.T) {
	v, err := vault.New(5 * time.Minute)
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	defer v.Close()

	secret1 := "AKIAIOSFODNN7EXAMPLE"
	secret2 := "sk-ant-api03-secret-token-value-1234567890"
	tok1, err := v.Store("sess-sse", secret1)
	if err != nil {
		t.Fatalf("store secret1: %v", err)
	}
	tok2, err := v.Store("sess-sse", secret2)
	if err != nil {
		t.Fatalf("store secret2: %v", err)
	}

	fullStream := fmt.Sprintf(
		"data: {\"delta\":\"Using key %s\"}\n\ndata: {\"delta\":\" and %s done\"}\n\n",
		tok1, tok2,
	)
	expected := fmt.Sprintf(
		"data: {\"delta\":\"Using key %s\"}\n\ndata: {\"delta\":\" and %s done\"}\n\n",
		secret1, secret2,
	)

	// Subtest 1: Explicit mid-token boundary split (__TS_TOK_1a / 2b3c4d__).
	t.Run("explicit_mid_token_split", func(t *testing.T) {
		splitAt := strings.Index(fullStream, tok1) + 11 // "__TS_TOK_xx"
		splitAt2 := strings.Index(fullStream, tok2) + 5 // "__TS_"
		chunks := [][]byte{
			[]byte(fullStream[:splitAt]),
			[]byte(fullStream[splitAt:splitAt2]),
			[]byte(fullStream[splitAt2:]),
		}
		detok := NewStreamDeTokenizer(&chunkedReader{chunks: chunks}, v, "sess-sse")
		out, err := io.ReadAll(detok)
		if err != nil {
			t.Fatalf("ReadAll failed: %v", err)
		}
		if string(out) != expected {
			t.Fatalf("reconstructed mismatch:\ngot:  %q\nwant: %q", string(out), expected)
		}
	})

	// Subtest 2: Arbitrary upstream and caller chunk sizes (1, 7, 64 bytes).
	for _, chunkSize := range []int{1, 7, 64} {
		t.Run(fmt.Sprintf("chunk_%d_bytes", chunkSize), func(t *testing.T) {
			var chunks [][]byte
			for i := 0; i < len(fullStream); i += chunkSize {
				end := i + chunkSize
				if end > len(fullStream) {
					end = len(fullStream)
				}
				chunks = append(chunks, []byte(fullStream[i:end]))
			}
			detok := NewStreamDeTokenizer(&chunkedReader{chunks: chunks}, v, "sess-sse")
			var got bytes.Buffer
			readBuf := make([]byte, chunkSize)
			for {
				n, err := detok.Read(readBuf)
				if n > 0 {
					got.Write(readBuf[:n])
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("read error: %v", err)
				}
			}
			if got.String() != expected {
				t.Fatalf("chunk size %d mismatch:\ngot:  %q\nwant: %q", chunkSize, got.String(), expected)
			}
		})
	}
}

func TestAdminEndpointsAndBearerAuth(t *testing.T) {
	v, err := vault.New(5 * time.Minute)
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	defer v.Close()

	cfg := config.Default()
	p, err := redact.NewPipeline(cfg.Security, v, audit.NewWriter(io.Discard))
	if err != nil {
		t.Fatalf("create pipeline: %v", err)
	}
	srv, err := NewServer(cfg, v, p, audit.NewWriter(io.Discard))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	adminHandler := srv.AdminHandler()
	for _, tc := range []struct {
		path string
		code int
		want string
	}{
		{"/healthz", http.StatusOK, `"status":"ok"`},
		{"/readyz", http.StatusOK, `"status":"ready"`},
		{"/metrics", http.StatusOK, "tracescrub_requests_total"},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		rec := httptest.NewRecorder()
		adminHandler.ServeHTTP(rec, req)
		if rec.Code != tc.code {
			t.Fatalf("%s status = %d, want %d", tc.path, rec.Code, tc.code)
		}
		if !strings.Contains(rec.Body.String(), tc.want) {
			t.Fatalf("%s body %q missing %q", tc.path, rec.Body.String(), tc.want)
		}
	}

	// Mutating endpoint requires bearer token.
	unauthReq := httptest.NewRequest(http.MethodPost, "/admin/vault/purge", nil)
	unauthRec := httptest.NewRecorder()
	adminHandler.ServeHTTP(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without bearer token, got %d", unauthRec.Code)
	}

	authReq := httptest.NewRequest(http.MethodPost, "/admin/vault/purge", nil)
	authReq.Header.Set("Authorization", "Bearer "+srv.AdminToken())
	authRec := httptest.NewRecorder()
	adminHandler.ServeHTTP(authRec, authReq)
	if authRec.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid bearer token, got %d", authRec.Code)
	}
}

func TestProxyFailClosedUnit(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	v, err := vault.New(5 * time.Minute)
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	defer v.Close()

	cfg := config.Default()
	cfg.Server.MaxBodyBytes = 128
	cfg.Upstream.DefaultTarget = upstream.URL
	cfg.Security.StrictMode = true

	p, err := redact.NewPipeline(cfg.Security, v, audit.NewWriter(io.Discard))
	if err != nil {
		t.Fatalf("create pipeline: %v", err)
	}
	srv, err := NewServer(cfg, v, p, audit.NewWriter(io.Discard))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	// 1. Oversized body -> 413
	bigBody := strings.Repeat("a", 256)
	rec1 := httptest.NewRecorder()
	srv.ProxyHandler().ServeHTTP(rec1, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(bigBody)))
	if rec1.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rec1.Code)
	}

	// 2. Malformed JSON with strict_mode: true -> 403
	rec2 := httptest.NewRecorder()
	srv.ProxyHandler().ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader("{bad json")))
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec2.Code)
	}

	// 3. Vault failure -> 502
	v.SetSimulateFailure(true)
	rec3 := httptest.NewRecorder()
	srv.ProxyHandler().ServeHTTP(rec3, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"msg":"AKIAIOSFODNN7EXAMPLE"}`)))
	if rec3.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rec3.Code)
	}
	v.SetSimulateFailure(false)

	if upstreamHits.Load() != 0 {
		t.Fatalf("expected 0 upstream hits on fail-closed blocks, got %d", upstreamHits.Load())
	}
}

func makeProxyBenchPayload(targetBytes int) []byte {
	snippet := `func verifyHandler(ctx context.Context, id string) string { return "ok:" + id }`
	var msgs []map[string]any
	total := 0
	for i := 0; total < targetBytes; i++ {
		content := snippet
		if i == 0 {
			content = "key=AKIAIOSFODNN7EXAMPLE " + snippet
		}
		msgs = append(msgs, map[string]any{"role": "user", "content": content})
		total += len(content) + 28
	}
	b, _ := json.Marshal(map[string]any{"model": "gpt-4o", "messages": msgs})
	return b
}

func benchmarkProxyPayload(b *testing.B, targetBytes int) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"ok","choices":[{"message":{"content":"done"}}]}`))
	}))
	defer upstream.Close()

	v, err := vault.New(5 * time.Minute)
	if err != nil {
		b.Fatalf("vault: %v", err)
	}
	defer v.Close()

	cfg := config.Default()
	cfg.Upstream.DefaultTarget = upstream.URL
	p, err := redact.NewPipeline(cfg.Security, v, audit.NewWriter(io.Discard))
	if err != nil {
		b.Fatalf("pipeline: %v", err)
	}
	srv, err := NewServer(cfg, v, p, audit.NewWriter(io.Discard))
	if err != nil {
		b.Fatalf("server: %v", err)
	}
	handler := srv.ProxyHandler()
	payload := makeProxyBenchPayload(targetBytes)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(payload))
		req.Header.Set("X-TraceScrub-Session", "bench-proxy")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status: %d", rec.Code)
		}
	}
}

// QA-09: 10 KB proxy + redaction benchmark.
func BenchmarkProxy_10KB(b *testing.B) {
	benchmarkProxyPayload(b, 10*1024)
}

// QA-09: 100 KB proxy + redaction benchmark.
func BenchmarkProxy_100KB(b *testing.B) {
	benchmarkProxyPayload(b, 100*1024)
}
