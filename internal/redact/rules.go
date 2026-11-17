package redact

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/tracescrub/tracescrub/internal/config"
)

// Rule defines a deterministic regex secret detection rule.
type Rule struct {
	ID                   string
	Pattern              *regexp.Regexp
	ReplacementPrefix    string
	RequiresLeftBoundary bool
	QuickHint            string
	QuickHintByte        byte
	MinLen               int
}

// RuleSet holds compiled built-in rules, custom org rules, and allowlist patterns.
type RuleSet struct {
	Rules     []Rule
	Allowlist []*regexp.Regexp
}

// NewRuleSet compiles built-in rules, custom configuration rules, and allowlist regexes.
func NewRuleSet(cfg config.SecurityConfig) (*RuleSet, error) {
	builtIn := []Rule{
		{
			ID:                "pem-private-key",
			Pattern:           regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`),
			ReplacementPrefix: "PEM",
			QuickHint:         "-----BEGIN ",
			MinLen:            40,
		},
		{
			ID:                "db-connection-url",
			Pattern:           regexp.MustCompile(`(postgres|postgresql|mysql|mongodb|redis|amqp)://[^:\s]+:[^@\s]+@[^\s"']+`),
			ReplacementPrefix: "DBURL",
			QuickHint:         "://",
			MinLen:            12,
		},
		{
			ID:                   "jwt-token",
			Pattern:              regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
			ReplacementPrefix:    "JWT",
			RequiresLeftBoundary: true,
			QuickHint:            "eyJ",
			MinLen:               38,
		},
		{
			ID:                   "aws-access-key-id",
			Pattern:              regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
			ReplacementPrefix:    "AWS",
			RequiresLeftBoundary: true,
			QuickHintByte:        'A',
			MinLen:               20,
		},
		{
			ID:                   "github-token",
			Pattern:              regexp.MustCompile(`(?:(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22,255})`),
			ReplacementPrefix:    "GITHUB",
			RequiresLeftBoundary: true,
			QuickHint:            "gh",
			MinLen:               33,
		},
		{
			ID:                   "llm-api-key",
			Pattern:              regexp.MustCompile(`(?:sk-ant-[A-Za-z0-9\-_]{20,}|sk-[A-Za-z0-9\-_]{20,}|fw_[A-Za-z0-9]{20,})`),
			ReplacementPrefix:    "LLM",
			RequiresLeftBoundary: true,
			MinLen:               23,
		},
	}

	rules := make([]Rule, 0, len(builtIn)+len(cfg.CustomRules))
	rules = append(rules, builtIn...)

	for _, cr := range cfg.CustomRules {
		re, err := regexp.Compile(cr.Pattern)
		if err != nil {
			return nil, fmt.Errorf("redact: compile custom rule %q: %w", cr.ID, err)
		}
		rules = append(rules, Rule{
			ID:                cr.ID,
			Pattern:           re,
			ReplacementPrefix: cr.ReplacementPrefix,
		})
	}

	allowlist := make([]*regexp.Regexp, 0, len(cfg.AllowlistPatterns))
	for _, pat := range cfg.AllowlistPatterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("redact: compile allowlist pattern %q: %w", pat, err)
		}
		allowlist = append(allowlist, re)
	}

	return &RuleSet{
		Rules:     rules,
		Allowlist: allowlist,
	}, nil
}

// IsAllowlisted reports whether a candidate secret matches any configured allowlist pattern.
func (rs *RuleSet) IsAllowlisted(candidate string) bool {
	if strings.HasPrefix(candidate, "__TS_TOK_") && strings.HasSuffix(candidate, "__") && len(candidate) == 19 {
		return true
	}
	for _, re := range rs.Allowlist {
		if re.MatchString(candidate) {
			return true
		}
	}
	return false
}

func (r *Rule) mightMatch(s string) bool {
	if len(s) < r.MinLen {
		return false
	}
	if r.QuickHintByte != 0 && strings.IndexByte(s, r.QuickHintByte) < 0 {
		return false
	}
	if r.QuickHint != "" && !strings.Contains(s, r.QuickHint) {
		return false
	}
	if r.ID == "llm-api-key" && !strings.Contains(s, "sk-") && !strings.Contains(s, "fw_") {
		return false
	}
	return true
}

func isAlphaNum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}
