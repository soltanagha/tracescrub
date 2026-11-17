package redact

import (
	"math"
	"regexp"
)

const contextWindowBytes = 64

var (
	candidateTokenRegex = regexp.MustCompile(`[A-Za-z0-9+/_-]{20,}={0,2}`)
	uuidRegex           = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexHashRegex        = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

// strongContextKeywords trigger regardless of word boundary (e.g., api_key, secret, token).
var strongContextKeywords = []string{
	"api_key",
	"apikey",
	"secret",
	"token",
	"password",
	"passwd",
	"authorization",
	"bearer",
	"credential",
}

// boundaryContextKeywords require identifier/word boundaries so words like "keyboard" or "author" don't match.
var boundaryContextKeywords = []string{
	"key",
	"auth",
}

// EntropyMatch describes a high-entropy secret span detected inside a string.
type EntropyMatch struct {
	Start   int
	End     int
	Secret  string
	Entropy float64
}

// ShannonEntropy computes the Shannon entropy (in bits per byte) of s.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	length := float64(len(s))
	var entropy float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// HasContextKeyword reports whether s contains a secret-related context keyword
// without heap allocations.
func HasContextKeyword(s string) bool {
	if len(s) < 3 {
		return false
	}
	for _, kw := range strongContextKeywords {
		if indexASCIIFold(s, kw, 0) >= 0 {
			return true
		}
	}
	for _, kw := range boundaryContextKeywords {
		if containsBoundaryKeyword(s, kw) {
			return true
		}
	}
	return false
}

// FindHighEntropySecrets locates contiguous candidate tokens of length >= minLen
// with ShannonEntropy >= threshold appearing within 64 characters of a context keyword
// (or under a parent JSON key containing a context keyword).
func FindHighEntropySecrets(text string, parentKey string, minLen int, threshold float64, rs *RuleSet) []EntropyMatch {
	if len(text) < minLen {
		return nil
	}

	parentHasKeyword := HasContextKeyword(parentKey)
	textHasKeyword := HasContextKeyword(text)
	if !parentHasKeyword && !textHasKeyword {
		return nil
	}

	indices := candidateTokenRegex.FindAllStringIndex(text, -1)
	if len(indices) == 0 {
		return nil
	}

	var matches []EntropyMatch
	for _, idx := range indices {
		start, end := idx[0], idx[1]
		cand := text[start:end]
		if len(cand) < minLen {
			continue
		}
		if uuidRegex.MatchString(cand) {
			continue
		}
		if hexHashRegex.MatchString(cand) {
			// Pure hex has theoretical max Shannon entropy of 4.0 (< 4.5).
			continue
		}
		if rs != nil && rs.IsAllowlisted(cand) {
			continue
		}

		// Check if candidate itself is just a context keyword or normal non-secret word.
		if !parentHasKeyword {
			winStart := start - contextWindowBytes
			if winStart < 0 {
				winStart = 0
			}
			winEnd := end + contextWindowBytes
			if winEnd > len(text) {
				winEnd = len(text)
			}
			// Check the 64-char windows immediately before and after the candidate token.
			before := text[winStart:start]
			after := text[end:winEnd]
			if !HasContextKeyword(before) && !HasContextKeyword(after) {
				continue
			}
		}

		h := ShannonEntropy(cand)
		if h >= threshold {
			matches = append(matches, EntropyMatch{
				Start:   start,
				End:     end,
				Secret:  cand,
				Entropy: h,
			})
		}
	}
	return matches
}

func containsBoundaryKeyword(orig, kw string) bool {
	offset := 0
	for {
		start := indexASCIIFold(orig, kw, offset)
		if start < 0 {
			return false
		}
		end := start + len(kw)

		leftOK := start == 0 || !isLowerAlphaNum(orig[start-1])
		rightOK := end == len(orig) || !isLowerAlphaNum(orig[end])
		// Also accept camelCase transition like apiKey / authToken where left or right switches case.
		if !leftOK && orig[start] >= 'A' && orig[start] <= 'Z' {
			leftOK = true
		}
		if !rightOK && orig[end] >= 'A' && orig[end] <= 'Z' {
			rightOK = true
		}
		if leftOK && rightOK {
			return true
		}
		offset = start + len(kw)
	}
}

func indexASCIIFold(s, lowerNeedle string, start int) int {
	nLen := len(lowerNeedle)
	if nLen == 0 {
		return start
	}
	limit := len(s) - nLen
	if start > limit {
		return -1
	}
	first := lowerNeedle[0]
	firstUpper := first
	if first >= 'a' && first <= 'z' {
		firstUpper = first - 32
	}
	for i := start; i <= limit; i++ {
		c := s[i]
		if c != first && c != firstUpper {
			continue
		}
		matched := true
		for j := 1; j < nLen; j++ {
			b := s[i+j]
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			if b != lowerNeedle[j] {
				matched = false
				break
			}
		}
		if matched {
			return i
		}
	}
	return -1
}

func isLowerAlphaNum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}
