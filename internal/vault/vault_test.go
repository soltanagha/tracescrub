package vault

import (
	"errors"
	"fmt"
	"regexp"
	"sync"
	"testing"
	"time"
)

var tokenFormatRegex = regexp.MustCompile(`^__TS_TOK_[a-f0-9]{8}__$`)

func TestVaultEncryptDecryptAndTokenFormat(t *testing.T) {
	v, err := New(5 * time.Minute)
	if err != nil {
		t.Fatalf("failed to create vault: %v", err)
	}
	defer v.Close()

	secret := "sk-ant-api03-very-secret-test-value-99999"
	tok1, err := v.Store("sess-1", secret)
	if err != nil {
		t.Fatalf("store failed: %v", err)
	}
	if len(tok1) != TokenLength {
		t.Fatalf("expected token length %d, got %d (%q)", TokenLength, len(tok1), tok1)
	}
	if !tokenFormatRegex.MatchString(tok1) {
		t.Fatalf("token %q did not match required format", tok1)
	}

	// Deterministic within the same session.
	tok2, err := v.Store("sess-1", secret)
	if err != nil {
		t.Fatalf("second store failed: %v", err)
	}
	if tok1 != tok2 {
		t.Fatalf("expected deterministic token within session, got %q vs %q", tok1, tok2)
	}

	got, err := v.Resolve("sess-1", tok1)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if got != secret {
		t.Fatalf("resolved secret mismatch: got %q, want %q", got, secret)
	}
}

func TestVaultSessionIsolation(t *testing.T) {
	v, err := New(5 * time.Minute)
	if err != nil {
		t.Fatalf("failed to create vault: %v", err)
	}
	defer v.Close()

	secret := "AKIAIOSFODNN7EXAMPLE"
	tokA, err := v.Store("session-A", secret)
	if err != nil {
		t.Fatalf("store in session-A failed: %v", err)
	}
	tokB, err := v.Store("session-B", secret)
	if err != nil {
		t.Fatalf("store in session-B failed: %v", err)
	}
	if tokA == tokB {
		t.Fatalf("expected distinct tokens across sessions, got identical %q", tokA)
	}

	if _, err := v.Resolve("session-B", tokA); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("expected ErrTokenNotFound on cross-session lookup, got %v", err)
	}
	if _, err := v.Resolve("session-A", tokB); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("expected ErrTokenNotFound on cross-session lookup, got %v", err)
	}
}

func TestVaultTTLExpirationAndEviction(t *testing.T) {
	var mu sync.Mutex
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}

	v, err := New(30*time.Second, WithClock(clock), WithEvictionInterval(10*time.Millisecond))
	if err != nil {
		t.Fatalf("failed to create vault: %v", err)
	}
	defer v.Close()

	tok, err := v.Store("sess-ttl", "ghp_1234567890abcdefghijklmnopqrstuvwxyz")
	if err != nil {
		t.Fatalf("store failed: %v", err)
	}

	if got, err := v.Resolve("sess-ttl", tok); err != nil || got == "" {
		t.Fatalf("expected valid resolve before TTL, got err=%v", err)
	}

	advance(31 * time.Second)

	if _, err := v.Resolve("sess-ttl", tok); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired after TTL, got %v", err)
	}

	// Ensure background ticker purges expired entries as well.
	tok2, err := v.Store("sess-ttl", "fw_abcdef1234567890abcdef123456")
	if err != nil {
		t.Fatalf("store tok2 failed: %v", err)
	}
	if tok2 == "" || v.Len() == 0 {
		t.Fatal("expected tok2 to be stored")
	}
	advance(31 * time.Second)

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if v.Len() == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if v.Len() != 0 {
		t.Fatalf("expected background eviction to purge expired entries, remaining=%d", v.Len())
	}
}

func TestVaultConcurrentAccessRace(t *testing.T) {
	v, err := New(2*time.Minute, WithEvictionInterval(5*time.Millisecond))
	if err != nil {
		t.Fatalf("failed to create vault: %v", err)
	}
	defer v.Close()

	const workers = 16
	const ops = 100
	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		go func(workerID int) {
			defer wg.Done()
			sessionID := fmt.Sprintf("sess-%d", workerID%4)
			for i := 0; i < ops; i++ {
				secret := fmt.Sprintf("secret-worker-%d-item-%d-abcdefghijkl", workerID, i)
				tok, err := v.Store(sessionID, secret)
				if err != nil {
					t.Errorf("concurrent store error: %v", err)
					return
				}
				resolved, err := v.Resolve(sessionID, tok)
				if err != nil {
					t.Errorf("concurrent resolve error: %v", err)
					return
				}
				if resolved != secret {
					t.Errorf("resolved mismatch: got %q, want %q", resolved, secret)
					return
				}
			}
		}(w)
	}
	wg.Wait()
}
