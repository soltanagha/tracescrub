package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoggerWritesStructuredJSONLWithHashes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := New(true, path)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}

	logger.Emit(Event{
		EventType: "secret_redacted",
		SessionID: "sess-123",
		RuleID:    "aws-access-key-id",
		Action:    "tokenize",
		Status:    "redacted",
		TokenID:   "__TS_TOK_deadbeef__",
		Details: map[string]string{
			"field_path": "messages[0].content",
		},
	})
	if err := logger.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit log failed: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		t.Fatal("expected at least one audit log line")
	}
	line := scanner.Text()
	var parsed map[string]any
	if err := json.Unmarshal([]byte(line), &parsed); err != nil {
		t.Fatalf("invalid jsonl line: %v", err)
	}

	for _, field := range []string{"timestamp", "event_type", "session_id", "rule_id", "rule_id_sha256", "event_hash_sha256", "action", "status"} {
		val, ok := parsed[field].(string)
		if !ok || strings.TrimSpace(val) == "" {
			t.Fatalf("missing or empty required field %q in %v", field, parsed)
		}
	}

	if got := parsed["rule_id_sha256"].(string); len(got) != 64 {
		t.Fatalf("expected 64-char hex rule_id_sha256, got %q", got)
	}
	if got := parsed["event_hash_sha256"].(string); len(got) != 64 {
		t.Fatalf("expected 64-char hex event_hash_sha256, got %q", got)
	}
}
