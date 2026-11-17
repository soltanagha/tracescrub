package proxy

import (
	"bytes"
	"io"
	"strings"

	"github.com/tracescrub/tracescrub/internal/vault"
)

const (
	// LookaheadSize is len("__TS_TOK_00000000__") - 1 = 18 bytes.
	LookaheadSize = vault.TokenLength - 1
	readChunkSize = 4096
)

var tokenPrefixBytes = []byte(vault.TokenPrefix)

// StreamDeTokenizer wraps an upstream io.ReadCloser and de-tokenizes
// __TS_TOK_<8_hex>__ placeholders on the fly across arbitrary SSE chunk boundaries
// using a bounded 18-byte lookahead sliding window.
type StreamDeTokenizer struct {
	src       io.ReadCloser
	vault     *vault.EphemeralVault
	sessionID string
	inBuf     []byte
	outBuf    []byte
	scratch   []byte
	eof       bool
	readErr   error
}

// NewStreamDeTokenizer constructs a sliding-window SSE de-tokenizer around src.
func NewStreamDeTokenizer(src io.ReadCloser, v *vault.EphemeralVault, sessionID string) *StreamDeTokenizer {
	return &StreamDeTokenizer{
		src:       src,
		vault:     v,
		sessionID: sessionID,
		scratch:   make([]byte, readChunkSize),
	}
}

// Read implements io.Reader, guaranteeing tokens split across upstream chunks
// are reconstructed completely before leaving outBuf.
func (s *StreamDeTokenizer) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	for len(s.outBuf) == 0 {
		if s.eof && len(s.inBuf) == 0 {
			if s.readErr != nil {
				return 0, s.readErr
			}
			return 0, io.EOF
		}

		if !s.eof {
			n, err := s.src.Read(s.scratch)
			if n > 0 {
				s.inBuf = append(s.inBuf, s.scratch[:n]...)
			}
			if err != nil {
				s.eof = true
				if err != io.EOF {
					s.readErr = err
				}
			}
		}

		s.processBuffer()
	}

	copied := copy(p, s.outBuf)
	if copied == len(s.outBuf) {
		s.outBuf = s.outBuf[:0]
	} else {
		remaining := copy(s.outBuf, s.outBuf[copied:])
		s.outBuf = s.outBuf[:remaining]
	}

	if len(s.outBuf) == 0 && s.eof && len(s.inBuf) == 0 {
		if s.readErr != nil {
			return copied, s.readErr
		}
		return copied, io.EOF
	}
	return copied, nil
}

// Close closes the underlying ReadCloser.
func (s *StreamDeTokenizer) Close() error {
	if s.src != nil {
		return s.src.Close()
	}
	return nil
}

func (s *StreamDeTokenizer) processBuffer() {
	for len(s.inBuf) > 0 {
		idx := bytes.Index(s.inBuf, tokenPrefixBytes)
		if idx < 0 {
			if s.eof {
				s.outBuf = append(s.outBuf, s.inBuf...)
				s.inBuf = s.inBuf[:0]
				return
			}
			hold := trailingPrefixLen(s.inBuf)
			emitLen := len(s.inBuf) - hold
			if emitLen > 0 {
				s.outBuf = append(s.outBuf, s.inBuf[:emitLen]...)
				s.consumeInBuf(emitLen)
			}
			return
		}

		if idx > 0 {
			s.outBuf = append(s.outBuf, s.inBuf[:idx]...)
			s.consumeInBuf(idx)
		}

		if len(s.inBuf) < vault.TokenLength {
			if s.eof || !isPotentialTokenPrefix(s.inBuf) {
				if s.eof {
					s.outBuf = append(s.outBuf, s.inBuf...)
					s.inBuf = s.inBuf[:0]
					return
				}
				// Not a valid partial token prefix; emit 1 byte and continue scanning.
				s.outBuf = append(s.outBuf, s.inBuf[0])
				s.consumeInBuf(1)
				continue
			}
			// Hold up to LookaheadSize (18 bytes) until next chunk completes the token.
			return
		}

		candidate := string(s.inBuf[:vault.TokenLength])
		if IsValidTokenFormat(candidate) {
			if s.vault != nil {
				if secret, err := s.vault.Resolve(s.sessionID, candidate); err == nil {
					s.outBuf = append(s.outBuf, secret...)
					s.consumeInBuf(vault.TokenLength)
					continue
				}
			}
			s.outBuf = append(s.outBuf, candidate...)
			s.consumeInBuf(vault.TokenLength)
			continue
		}

		// False prefix (e.g. __TS_TOK_nothex__), advance by 1 byte so adjacent tokens aren't skipped.
		s.outBuf = append(s.outBuf, s.inBuf[0])
		s.consumeInBuf(1)
	}
}

func (s *StreamDeTokenizer) consumeInBuf(n int) {
	if n >= len(s.inBuf) {
		s.inBuf = s.inBuf[:0]
		return
	}
	rem := copy(s.inBuf, s.inBuf[n:])
	s.inBuf = s.inBuf[:rem]
}

// DetokenizeBytes scans a complete non-streaming payload and replaces valid
// session tokens with their decrypted secrets from the vault.
func DetokenizeBytes(v *vault.EphemeralVault, sessionID string, data []byte) []byte {
	if v == nil || len(data) < vault.TokenLength || !bytes.Contains(data, tokenPrefixBytes) {
		return data
	}

	var out strings.Builder
	out.Grow(len(data))
	pos := 0
	for pos < len(data) {
		idx := bytes.Index(data[pos:], tokenPrefixBytes)
		if idx < 0 {
			out.Write(data[pos:])
			break
		}
		out.Write(data[pos : pos+idx])
		pos += idx
		if pos+vault.TokenLength <= len(data) {
			cand := string(data[pos : pos+vault.TokenLength])
			if IsValidTokenFormat(cand) {
				if secret, err := v.Resolve(sessionID, cand); err == nil {
					out.WriteString(secret)
					pos += vault.TokenLength
					continue
				}
			}
		}
		out.WriteByte(data[pos])
		pos++
	}
	return []byte(out.String())
}

// IsValidTokenFormat checks whether s matches __TS_TOK_<8_lowercase_hex_chars>__.
func IsValidTokenFormat(s string) bool {
	if len(s) != vault.TokenLength {
		return false
	}
	if !strings.HasPrefix(s, vault.TokenPrefix) || !strings.HasSuffix(s, vault.TokenSuffix) {
		return false
	}
	for i := len(vault.TokenPrefix); i < len(vault.TokenPrefix)+8; i++ {
		if !isLowerHex(s[i]) {
			return false
		}
	}
	return true
}

func isPotentialTokenPrefix(b []byte) bool {
	if len(b) > LookaheadSize {
		return false
	}
	for i, ch := range b {
		switch {
		case i < len(tokenPrefixBytes):
			if ch != tokenPrefixBytes[i] {
				return false
			}
		case i < len(tokenPrefixBytes)+8:
			if !isLowerHex(ch) {
				return false
			}
		default:
			if ch != '_' {
				return false
			}
		}
	}
	return true
}

func trailingPrefixLen(b []byte) int {
	maxCheck := len(tokenPrefixBytes) - 1
	if len(b) < maxCheck {
		maxCheck = len(b)
	}
	for k := maxCheck; k >= 1; k-- {
		if bytes.Equal(b[len(b)-k:], tokenPrefixBytes[:k]) {
			return k
		}
	}
	return 0
}

func isLowerHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')
}
