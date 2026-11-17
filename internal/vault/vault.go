package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// TokenPrefix is the fixed 9-byte prefix of every TraceScrub placeholder token.
	TokenPrefix = "__TS_TOK_"
	// TokenSuffix is the fixed 2-byte suffix of every TraceScrub placeholder token.
	TokenSuffix = "__"
	// TokenLength is the exact byte length of __TS_TOK_<8_hex>__ (19 bytes).
	TokenLength = 19
	// DefaultEvictionInterval is the background ticker interval for purging expired tokens.
	DefaultEvictionInterval = 30 * time.Second
)

var (
	// ErrInvalidInput indicates an empty session ID or secret/token input.
	ErrInvalidInput = errors.New("vault: session_id and secret/token must be non-empty")
	// ErrTokenNotFound indicates the token does not exist in the specified session.
	ErrTokenNotFound = errors.New("vault: token not found for session")
	// ErrTokenExpired indicates the token has exceeded its configured TTL.
	ErrTokenExpired = errors.New("vault: token expired")
	// ErrVaultClosed indicates the vault has been closed and zeroed.
	ErrVaultClosed = errors.New("vault: closed")
	// ErrVaultUnavailable indicates a simulated or runtime vault failure.
	ErrVaultUnavailable = errors.New("vault: unavailable")
)

type sessionTokenKey struct {
	sessionID string
	token     string
}

type vaultEntry struct {
	ciphertext []byte
	nonce      []byte
	secretMAC  [32]byte
	expiresAt  time.Time
}

// EphemeralVault stores secrets strictly in memory encrypted with AES-256-GCM
// using a per-process 32-byte key and scoped to (session_id, token_id).
type EphemeralVault struct {
	mu              sync.RWMutex
	key             []byte
	hmacKey         []byte
	aead            cipher.AEAD
	ttl             time.Duration
	evictInterval   time.Duration
	nowFn           func() time.Time
	entries         map[sessionTokenKey]*vaultEntry
	stopCh          chan struct{}
	doneCh          chan struct{}
	closed          atomic.Bool
	simulateFailure atomic.Bool
}

// Option customizes an EphemeralVault instance (primarily for testing).
type Option func(*EphemeralVault)

// WithEvictionInterval overrides the default 30-second background eviction interval.
func WithEvictionInterval(d time.Duration) Option {
	return func(v *EphemeralVault) {
		if d > 0 {
			v.evictInterval = d
		}
	}
}

// WithClock overrides the time source for deterministic expiration testing.
func WithClock(fn func() time.Time) Option {
	return func(v *EphemeralVault) {
		if fn != nil {
			v.nowFn = fn
		}
	}
}

// New creates a new in-memory EphemeralVault with the specified token TTL.
func New(ttl time.Duration, opts ...Option) (*EphemeralVault, error) {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("vault: generate encryption key: %w", err)
	}
	hmacKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, hmacKey); err != nil {
		zeroBytes(key)
		return nil, fmt.Errorf("vault: generate hmac key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		zeroBytes(key)
		zeroBytes(hmacKey)
		return nil, fmt.Errorf("vault: create aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		zeroBytes(key)
		zeroBytes(hmacKey)
		return nil, fmt.Errorf("vault: create gcm aead: %w", err)
	}

	v := &EphemeralVault{
		key:           key,
		hmacKey:       hmacKey,
		aead:          aead,
		ttl:           ttl,
		evictInterval: DefaultEvictionInterval,
		nowFn:         time.Now,
		entries:       make(map[sessionTokenKey]*vaultEntry),
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
	for _, opt := range opts {
		opt(v)
	}

	go v.evictionLoop()
	return v, nil
}

// Ready reports whether the vault is initialized and open for operations.
func (v *EphemeralVault) Ready() bool {
	return v != nil && !v.closed.Load() && v.aead != nil
}

// SetSimulateFailure enables or disables simulated vault errors for fail-closed tests.
func (v *EphemeralVault) SetSimulateFailure(enabled bool) {
	v.simulateFailure.Store(enabled)
}

// Store encrypts a secret under the given sessionID and returns its 19-byte
// deterministic placeholder token (__TS_TOK_<8_hex>__).
func (v *EphemeralVault) Store(sessionID, secret string) (string, error) {
	if v == nil || v.closed.Load() {
		return "", ErrVaultClosed
	}
	if v.simulateFailure.Load() {
		return "", ErrVaultUnavailable
	}
	if sessionID == "" || secret == "" {
		return "", ErrInvalidInput
	}

	secretBytes := []byte(secret)
	defer zeroBytes(secretBytes)

	secretMAC := v.computeSecretMAC(sessionID, secretBytes)

	v.mu.Lock()
	defer v.mu.Unlock()

	if v.closed.Load() {
		return "", ErrVaultClosed
	}

	now := v.nowFn()
	var token string
	var key sessionTokenKey

	for attempt := uint32(0); ; attempt++ {
		token = v.deriveToken(sessionID, secretBytes, attempt)
		key = sessionTokenKey{sessionID: sessionID, token: token}
		existing, exists := v.entries[key]
		if !exists {
			break
		}
		if now.After(existing.expiresAt) {
			zeroEntry(existing)
			delete(v.entries, key)
			break
		}
		if hmac.Equal(existing.secretMAC[:], secretMAC[:]) {
			existing.expiresAt = now.Add(v.ttl)
			return token, nil
		}
	}

	nonce := make([]byte, v.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("vault: generate nonce: %w", err)
	}

	aad := buildAAD(sessionID, token)
	ciphertext := v.aead.Seal(nil, nonce, secretBytes, aad)

	v.entries[key] = &vaultEntry{
		ciphertext: ciphertext,
		nonce:      nonce,
		secretMAC:  secretMAC,
		expiresAt:  now.Add(v.ttl),
	}
	return token, nil
}

// Resolve decrypts and returns the secret associated with (sessionID, token).
// Cross-session lookups fail with ErrTokenNotFound and expired tokens return ErrTokenExpired.
func (v *EphemeralVault) Resolve(sessionID, token string) (string, error) {
	if v == nil || v.closed.Load() {
		return "", ErrVaultClosed
	}
	if v.simulateFailure.Load() {
		return "", ErrVaultUnavailable
	}
	if sessionID == "" || token == "" {
		return "", ErrInvalidInput
	}

	key := sessionTokenKey{sessionID: sessionID, token: token}

	v.mu.RLock()
	entry, exists := v.entries[key]
	if !exists {
		v.mu.RUnlock()
		return "", ErrTokenNotFound
	}
	now := v.nowFn()
	if now.After(entry.expiresAt) {
		v.mu.RUnlock()
		v.purgeIfExpired(key, now)
		return "", ErrTokenExpired
	}
	// Copy ciphertext & nonce under read lock so background eviction cannot zero them mid-Open.
	nonce := make([]byte, len(entry.nonce))
	copy(nonce, entry.nonce)
	ciphertext := make([]byte, len(entry.ciphertext))
	copy(ciphertext, entry.ciphertext)
	v.mu.RUnlock()

	defer zeroBytes(nonce)
	defer zeroBytes(ciphertext)

	aad := buildAAD(sessionID, token)
	plaintext, err := v.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return "", fmt.Errorf("vault: decrypt entry: %w", err)
	}
	defer zeroBytes(plaintext)

	return string(plaintext), nil
}

// Len returns the current number of entries held in memory.
func (v *EphemeralVault) Len() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.entries)
}

// PurgeExpired removes all expired entries and zeroes their encrypted buffers.
func (v *EphemeralVault) PurgeExpired() int {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := v.nowFn()
	removed := 0
	for k, entry := range v.entries {
		if now.After(entry.expiresAt) {
			zeroEntry(entry)
			delete(v.entries, k)
			removed++
		}
	}
	return removed
}

// Close stops the background eviction goroutine and zeroes all in-memory keys and entries.
func (v *EphemeralVault) Close() error {
	if v == nil {
		return nil
	}
	if !v.closed.CompareAndSwap(false, true) {
		return nil
	}

	close(v.stopCh)
	<-v.doneCh

	v.mu.Lock()
	defer v.mu.Unlock()
	for k, entry := range v.entries {
		zeroEntry(entry)
		delete(v.entries, k)
	}
	zeroBytes(v.key)
	zeroBytes(v.hmacKey)
	return nil
}

func (v *EphemeralVault) evictionLoop() {
	defer close(v.doneCh)
	ticker := time.NewTicker(v.evictInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			v.PurgeExpired()
		case <-v.stopCh:
			return
		}
	}
}

func (v *EphemeralVault) purgeIfExpired(key sessionTokenKey, now time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if entry, exists := v.entries[key]; exists && now.After(entry.expiresAt) {
		zeroEntry(entry)
		delete(v.entries, key)
	}
}

func (v *EphemeralVault) deriveToken(sessionID string, secret []byte, attempt uint32) string {
	mac := hmac.New(sha256.New, v.hmacKey)
	mac.Write([]byte(sessionID))
	mac.Write([]byte{0})
	mac.Write(secret)
	if attempt > 0 {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], attempt)
		mac.Write(buf[:])
	}
	sum := mac.Sum(nil)
	return TokenPrefix + hex.EncodeToString(sum[:4]) + TokenSuffix
}

func (v *EphemeralVault) computeSecretMAC(sessionID string, secret []byte) [32]byte {
	mac := hmac.New(sha256.New, v.hmacKey)
	mac.Write([]byte("mac:"))
	mac.Write([]byte(sessionID))
	mac.Write([]byte{0})
	mac.Write(secret)
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func buildAAD(sessionID, token string) []byte {
	aad := make([]byte, 0, len(sessionID)+1+len(token))
	aad = append(aad, sessionID...)
	aad = append(aad, 0)
	aad = append(aad, token...)
	return aad
}

func zeroEntry(e *vaultEntry) {
	if e == nil {
		return
	}
	zeroBytes(e.ciphertext)
	zeroBytes(e.nonce)
	clear(e.secretMAC[:])
}

func zeroBytes(b []byte) {
	clear(b)
}
