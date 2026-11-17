package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tracescrub/tracescrub/internal/audit"
	"github.com/tracescrub/tracescrub/internal/config"
	"github.com/tracescrub/tracescrub/internal/redact"
	"github.com/tracescrub/tracescrub/internal/vault"
)

const sessionHeader = "X-TraceScrub-Session"

type routeTarget struct {
	prefix string
	target *url.URL
}

type metricsStore struct {
	requestsTotal        atomic.Int64
	blockedRequestsTotal atomic.Int64

	latencyMu        sync.Mutex
	latencyCount     int64
	latencySumMs     float64
	lastLatencyMs    float64
	secretsByRuleMu  sync.Mutex
	secretsByRuleMap map[string]int64
}

func newMetricsStore() *metricsStore {
	return &metricsStore{
		secretsByRuleMap: make(map[string]int64),
	}
}

func (m *metricsStore) recordRequest(latencyMs float64, findings []redact.Finding) {
	m.requestsTotal.Add(1)

	m.latencyMu.Lock()
	m.latencyCount++
	m.latencySumMs += latencyMs
	m.lastLatencyMs = latencyMs
	m.latencyMu.Unlock()

	if len(findings) > 0 {
		m.secretsByRuleMu.Lock()
		for _, f := range findings {
			m.secretsByRuleMap[f.RuleID]++
		}
		m.secretsByRuleMu.Unlock()
	}
}

// Server implements the Zero-Trust Agent Egress Proxy and loopback Admin API.
type Server struct {
	cfg           *config.Config
	vault         *vault.EphemeralVault
	pipeline      *redact.Pipeline
	audit         *audit.Logger
	httpClient    *http.Client
	defaultTarget *url.URL
	routes        []routeTarget
	metrics       *metricsStore
	adminToken    string
	proxySrv      *http.Server
	adminSrv      *http.Server
	ready         atomic.Bool
}

// NewServer constructs a configured TraceScrub Server with proxy and admin handlers.
func NewServer(cfg *config.Config, v *vault.EphemeralVault, p *redact.Pipeline, a *audit.Logger) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("proxy: config cannot be nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if v == nil || p == nil {
		return nil, errors.New("proxy: vault and pipeline are required")
	}

	defURL, err := url.Parse(cfg.Upstream.DefaultTarget)
	if err != nil {
		return nil, fmt.Errorf("proxy: parse default target: %w", err)
	}

	routes := make([]routeTarget, 0, len(cfg.Upstream.Routes))
	for prefix, rawTarget := range cfg.Upstream.Routes {
		u, err := url.Parse(rawTarget)
		if err != nil {
			return nil, fmt.Errorf("proxy: parse route target %q: %w", prefix, err)
		}
		routes = append(routes, routeTarget{prefix: prefix, target: u})
	}
	// Longest prefix wins deterministically.
	sort.Slice(routes, func(i, j int) bool {
		if len(routes[i].prefix) == len(routes[j].prefix) {
			return routes[i].prefix < routes[j].prefix
		}
		return len(routes[i].prefix) > len(routes[j].prefix)
	})

	tokBytes := make([]byte, 32)
	if _, err := rand.Read(tokBytes); err != nil {
		return nil, fmt.Errorf("proxy: generate admin token: %w", err)
	}

	transport := &http.Transport{
		MaxIdleConns:        128,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     90 * time.Second,
	}

	s := &Server{
		cfg:           cfg,
		vault:         v,
		pipeline:      p,
		audit:         a,
		defaultTarget: defURL,
		routes:        routes,
		metrics:       newMetricsStore(),
		adminToken:    hex.EncodeToString(tokBytes),
		httpClient: &http.Client{
			Timeout:   cfg.UpstreamTimeout(),
			Transport: transport,
		},
	}
	s.ready.Store(true)
	return s, nil
}

// AdminToken returns the bearer token required for mutating admin operations.
func (s *Server) AdminToken() string {
	return s.adminToken
}

// ProxyHandler returns the HTTP handler for LLM API egress traffic.
func (s *Server) ProxyHandler() http.Handler {
	return http.HandlerFunc(s.handleProxy)
}

// AdminHandler returns the HTTP handler for /healthz, /readyz, /metrics, and admin operations.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/admin/vault/purge", s.requireAdminAuth(s.handleVaultPurge))
	return mux
}

// ListenAndServe starts both the proxy and loopback admin HTTP servers until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	s.proxySrv = &http.Server{
		Addr:        s.cfg.Server.ListenAddr,
		Handler:     s.ProxyHandler(),
		ReadTimeout: s.cfg.ReadTimeout(),
	}
	s.adminSrv = &http.Server{
		Addr:        s.cfg.Server.AdminAddr,
		Handler:     s.AdminHandler(),
		ReadTimeout: s.cfg.ReadTimeout(),
	}

	errCh := make(chan error, 2)
	go func() {
		if err := s.proxySrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("proxy server: %w", err)
		}
	}()
	go func() {
		if err := s.adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("admin server: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(shutCtx)
		return nil
	case err := <-errCh:
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(shutCtx)
		return err
	}
}

// Shutdown gracefully stops both HTTP servers.
func (s *Server) Shutdown(ctx context.Context) error {
	s.ready.Store(false)
	var errs []error
	if s.proxySrv != nil {
		if err := s.proxySrv.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if s.adminSrv != nil {
		if err := s.adminSrv.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimSpace(r.Header.Get(sessionHeader))
	if sessionID == "" {
		sessionID = newEphemeralSessionID()
	}

	defer func() {
		if rec := recover(); rec != nil {
			s.blockRequest(w, sessionID, "strict-mode-panic", http.StatusBadGateway, "internal scanner panic; blocked fail-closed")
		}
	}()

	maxBody := s.cfg.Server.MaxBodyBytes
	if r.ContentLength > maxBody {
		s.blockRequest(w, sessionID, "max-body-bytes-exceeded", http.StatusRequestEntityTooLarge, "request body exceeds max_body_bytes")
		return
	}

	rawBody, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		s.blockRequest(w, sessionID, "request-read-error", http.StatusBadRequest, "failed to read request body")
		return
	}
	if int64(len(rawBody)) > maxBody {
		s.blockRequest(w, sessionID, "max-body-bytes-exceeded", http.StatusRequestEntityTooLarge, "request body exceeds max_body_bytes")
		return
	}

	outboundBody := rawBody
	var findings []redact.Finding
	start := time.Now()

	if len(bytes.TrimSpace(rawBody)) > 0 {
		scrubbed, found, scrubErr := s.pipeline.ScrubJSON(sessionID, rawBody)
		if scrubErr != nil {
			if errors.Is(scrubErr, redact.ErrInvalidJSON) {
				if s.cfg.Security.StrictMode {
					s.blockRequest(w, sessionID, "strict-mode-invalid-json", http.StatusForbidden, "malformed JSON rejected in strict_mode")
					return
				}
			} else {
				// Vault unavailable or scanner failure -> fail-closed 502.
				s.blockRequest(w, sessionID, "strict-mode-scanner-error", http.StatusBadGateway, "redaction pipeline failure; blocked fail-closed")
				return
			}
		} else {
			outboundBody = scrubbed
			findings = found
		}
	}

	latencyMs := float64(time.Since(start).Nanoseconds()) / 1e6
	s.metrics.recordRequest(latencyMs, findings)

	upstreamURL := s.resolveUpstreamURL(r.URL)
	upReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), bytes.NewReader(outboundBody))
	if err != nil {
		s.blockRequest(w, sessionID, "upstream-request-build-error", http.StatusBadGateway, "failed to build upstream request")
		return
	}

	copyRequestHeaders(upReq.Header, r.Header)
	upReq.ContentLength = int64(len(outboundBody))
	upReq.Header.Set("Content-Length", strconv.Itoa(len(outboundBody)))
	// Let Go's Transport handle transparent gzip decompression so response de-tokenizers see plaintext.
	upReq.Header.Del("Accept-Encoding")
	upReq.Header.Del(sessionHeader)

	resp, err := s.httpClient.Do(upReq)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "upstream request failed")
		return
	}
	defer resp.Body.Close()

	copyResponseHeaders(w.Header(), resp.Header)

	isSSE := strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream")
	if !s.cfg.Security.DetokenizeResponses {
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}

	if isSSE {
		w.Header().Del("Content-Length")
		w.WriteHeader(resp.StatusCode)
		s.streamDetokenizedSSE(w, resp.Body, sessionID)
		return
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "failed reading upstream response")
		return
	}
	detokenized := DetokenizeBytes(s.vault, sessionID, respBytes)
	w.Header().Set("Content-Length", strconv.Itoa(len(detokenized)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(detokenized)
}

func (s *Server) streamDetokenizedSSE(w http.ResponseWriter, body io.ReadCloser, sessionID string) {
	detok := NewStreamDeTokenizer(body, s.vault, sessionID)
	defer detok.Close()

	flusher, canFlush := w.(http.Flusher)
	reader := bufio.NewReaderSize(detok, 4096)
	buf := make([]byte, 4096)

	for {
		n, err := reader.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				return
			}
			if canFlush {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *Server) resolveUpstreamURL(reqURL *url.URL) *url.URL {
	base := s.defaultTarget
	for _, rt := range s.routes {
		if strings.HasPrefix(reqURL.Path, rt.prefix) {
			base = rt.target
			break
		}
	}
	resolved := *base
	resolved.Path = singleJoiningSlash(base.Path, reqURL.Path)
	resolved.RawQuery = reqURL.RawQuery
	return &resolved
}

func (s *Server) blockRequest(w http.ResponseWriter, sessionID, ruleID string, status int, msg string) {
	s.metrics.blockedRequestsTotal.Add(1)
	if s.audit != nil {
		s.audit.Emit(audit.Event{
			EventType: "request_blocked",
			SessionID: sessionID,
			RuleID:    ruleID,
			Action:    "block",
			Status:    "blocked",
			Details: map[string]string{
				"http_status": strconv.Itoa(status),
			},
		})
	}
	writeJSONError(w, status, msg)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.ready.Load() || s.cfg == nil || !s.vault.Ready() || s.pipeline == nil || s.httpClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	var b strings.Builder
	fmt.Fprintf(&b, "# HELP tracescrub_requests_total Total number of proxied requests.\n")
	fmt.Fprintf(&b, "# TYPE tracescrub_requests_total counter\n")
	fmt.Fprintf(&b, "tracescrub_requests_total %d\n", s.metrics.requestsTotal.Load())

	fmt.Fprintf(&b, "# HELP tracescrub_blocked_requests_total Total number of requests blocked fail-closed.\n")
	fmt.Fprintf(&b, "# TYPE tracescrub_blocked_requests_total counter\n")
	fmt.Fprintf(&b, "tracescrub_blocked_requests_total %d\n", s.metrics.blockedRequestsTotal.Load())

	fmt.Fprintf(&b, "# HELP tracescrub_secrets_redacted_total Total secrets redacted by rule_id.\n")
	fmt.Fprintf(&b, "# TYPE tracescrub_secrets_redacted_total counter\n")
	s.metrics.secretsByRuleMu.Lock()
	ruleIDs := make([]string, 0, len(s.metrics.secretsByRuleMap))
	for id := range s.metrics.secretsByRuleMap {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	for _, id := range ruleIDs {
		fmt.Fprintf(&b, "tracescrub_secrets_redacted_total{rule_id=%q} %d\n", id, s.metrics.secretsByRuleMap[id])
	}
	s.metrics.secretsByRuleMu.Unlock()

	s.metrics.latencyMu.Lock()
	avgLatency := 0.0
	if s.metrics.latencyCount > 0 {
		avgLatency = s.metrics.latencySumMs / float64(s.metrics.latencyCount)
	}
	lastLatency := s.metrics.lastLatencyMs
	s.metrics.latencyMu.Unlock()

	fmt.Fprintf(&b, "# HELP tracescrub_redaction_latency_ms Average and latest redaction pipeline latency in milliseconds.\n")
	fmt.Fprintf(&b, "# TYPE tracescrub_redaction_latency_ms gauge\n")
	fmt.Fprintf(&b, "tracescrub_redaction_latency_ms{stat=\"avg\"} %.4f\n", avgLatency)
	fmt.Fprintf(&b, "tracescrub_redaction_latency_ms{stat=\"last\"} %.4f\n", lastLatency)

	_, _ = io.WriteString(w, b.String())
}

func (s *Server) handleVaultPurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	removed := s.vault.PurgeExpired()
	writeJSON(w, http.StatusOK, map[string]any{"purged": removed})
}

func (s *Server) requireAdminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(authHeader, prefix) {
			writeJSONError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		provided := strings.TrimPrefix(authHeader, prefix)
		if subtle.ConstantTimeCompare([]byte(provided), []byte(s.adminToken)) != 1 {
			writeJSONError(w, http.StatusUnauthorized, "invalid bearer token")
			return
		}
		next(w, r)
	}
}

func copyRequestHeaders(dst, src http.Header) {
	for k, vals := range src {
		if isHopByHopHeader(k) {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func copyResponseHeaders(dst, src http.Header) {
	for k, vals := range src {
		if isHopByHopHeader(k) {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func isHopByHopHeader(k string) bool {
	switch strings.ToLower(k) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		if a == "" {
			return "/" + b
		}
		return a + "/" + b
	}
	return a + b
}

func newEphemeralSessionID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("ephemeral-%d", time.Now().UnixNano())
	}
	return "ephemeral-" + hex.EncodeToString(b[:])
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
