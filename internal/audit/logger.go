package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event represents a security or redaction audit record with zero raw secret fields.
type Event struct {
	EventType       string            `json:"event_type"`
	SessionID       string            `json:"session_id,omitempty"`
	RuleID          string            `json:"rule_id"`
	Action          string            `json:"action"`
	Status          string            `json:"status"`
	TokenID         string            `json:"token_id,omitempty"`
	Details         map[string]string `json:"details,omitempty"`
	Timestamp       string            `json:"timestamp,omitempty"`
	RuleIDSHA256    string            `json:"rule_id_sha256,omitempty"`
	EventHashSHA256 string            `json:"event_hash_sha256,omitempty"`
}

// Logger writes structured JSONL audit records using log/slog.
// Raw secrets are structurally excluded from the Event schema.
type Logger struct {
	mu      sync.Mutex
	enabled bool
	file    *os.File
	slog    *slog.Logger
	nowFn   func() time.Time
}

// New creates a structured JSONL audit logger writing to outputPath.
// When enabled is false, returned logger discards events without touching disk.
func New(enabled bool, outputPath string) (*Logger, error) {
	if !enabled {
		return &Logger{
			enabled: false,
			slog:    slog.New(slog.NewJSONHandler(io.Discard, nil)),
			nowFn:   time.Now,
		}, nil
	}
	if outputPath == "" {
		outputPath = "./tracescrub-audit.jsonl"
	}
	if dir := filepath.Dir(outputPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("audit: create log directory: %w", err)
		}
	}
	f, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open output file %q: %w", outputPath, err)
	}

	return &Logger{
		enabled: true,
		file:    f,
		slog:    slog.New(slog.NewJSONHandler(f, &slog.HandlerOptions{Level: slog.LevelInfo})),
		nowFn:   time.Now,
	}, nil
}

// NewWriter creates a Logger backed by an arbitrary io.Writer (useful for tests).
func NewWriter(w io.Writer) *Logger {
	if w == nil {
		w = io.Discard
	}
	return &Logger{
		enabled: true,
		slog:    slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})),
		nowFn:   time.Now,
	}
}

// Emit records a structured audit event with SHA-256 digests of rule_id and event metadata.
func (l *Logger) Emit(ev Event) {
	if l == nil || !l.enabled {
		return
	}

	ts := l.nowFn().UTC().Format(time.RFC3339Nano)
	ruleHash := sha256Hex(ev.RuleID)
	eventHash := sha256Hex(ts + "|" + ev.SessionID + "|" + ev.RuleID + "|" + ev.EventType + "|" + ev.Action + "|" + ev.Status)

	attrs := []any{
		slog.String("timestamp", ts),
		slog.String("event_type", ev.EventType),
		slog.String("session_id", ev.SessionID),
		slog.String("rule_id", ev.RuleID),
		slog.String("rule_id_sha256", ruleHash),
		slog.String("event_hash_sha256", eventHash),
		slog.String("action", ev.Action),
		slog.String("status", ev.Status),
	}
	if ev.TokenID != "" {
		attrs = append(attrs, slog.String("token_id", ev.TokenID))
	}
	if len(ev.Details) > 0 {
		attrs = append(attrs, slog.Any("details", ev.Details))
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.slog.Info("tracescrub_audit_event", attrs...)
}

// Close flushes and closes the underlying audit file if owned by the logger.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		return err
	}
	return nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
