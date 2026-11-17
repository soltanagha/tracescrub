package redact

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/tracescrub/tracescrub/internal/audit"
	"github.com/tracescrub/tracescrub/internal/config"
	"github.com/tracescrub/tracescrub/internal/vault"
)

const HighEntropyRuleID = "high-entropy-secret"

// ErrInvalidJSON indicates the request payload is not valid JSON.
var ErrInvalidJSON = errors.New("redact: invalid json payload")

// Finding records metadata for a single secret redaction (never containing raw secrets).
type Finding struct {
	RuleID    string
	TokenID   string
	FieldPath string
}

// Pipeline recursively walks JSON payloads, redacts detected secrets into an
// EphemeralVault, and emits structured non-secret audit events.
type Pipeline struct {
	rules   *RuleSet
	vault   *vault.EphemeralVault
	audit   *audit.Logger
	cfg     config.SecurityConfig
	entropy bool
}

// NewPipeline creates a redaction Pipeline configured with rules, vault, and audit logger.
func NewPipeline(cfg config.SecurityConfig, v *vault.EphemeralVault, auditLogger *audit.Logger) (*Pipeline, error) {
	if v == nil {
		return nil, errors.New("redact: vault cannot be nil")
	}
	rs, err := NewRuleSet(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.EntropyThreshold <= 0 {
		cfg.EntropyThreshold = 4.5
	}
	if cfg.MinEntropyLength <= 0 {
		cfg.MinEntropyLength = 20
	}
	return &Pipeline{
		rules:   rs,
		vault:   v,
		audit:   auditLogger,
		cfg:     cfg,
		entropy: true,
	}, nil
}

type pathSeg struct {
	key   string
	index int
	isIdx bool
}

func formatPath(segs []pathSeg) string {
	if len(segs) == 0 {
		return ""
	}
	var b strings.Builder
	for _, s := range segs {
		if s.isIdx {
			b.WriteByte('[')
			b.WriteString(strconv.Itoa(s.index))
			b.WriteByte(']')
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.WriteString(s.key)
	}
	return b.String()
}

// ScrubJSON parses body as JSON, recursively scrubs every string value, stores secrets
// in the session-scoped vault, and returns the scrubbed JSON bytes plus findings metadata.
func (p *Pipeline) ScrubJSON(sessionID string, body []byte) ([]byte, []Finding, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, nil, ErrInvalidJSON
	}

	var doc any
	if err := json.Unmarshal(trimmed, &doc); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}

	var findings []Finding
	var pathBuf [16]pathSeg
	scrubbed, err := p.walkValue(sessionID, "", pathBuf[:0], doc, &findings)
	if err != nil {
		return nil, nil, err
	}

	out, err := json.Marshal(scrubbed)
	if err != nil {
		return nil, nil, fmt.Errorf("redact: marshal scrubbed json: %w", err)
	}
	return out, findings, nil
}

// ScrubString applies deterministic rules and high-entropy detection to a single string.
func (p *Pipeline) ScrubString(sessionID, parentKey, fieldPath, input string, findings *[]Finding) (string, error) {
	return p.scrubStringSegs(sessionID, parentKey, fieldPath, nil, input, findings)
}

func (p *Pipeline) scrubStringSegs(sessionID, parentKey, fixedPath string, segs []pathSeg, input string, findings *[]Finding) (string, error) {
	if input == "" {
		return input, nil
	}

	current := input
	var err error

	for i := range p.rules.Rules {
		rule := &p.rules.Rules[i]
		if !rule.mightMatch(current) {
			continue
		}
		current, err = p.applyRegexRule(sessionID, fixedPath, segs, current, rule, findings)
		if err != nil {
			return "", err
		}
	}

	if p.entropy {
		current, err = p.applyEntropyRule(sessionID, parentKey, fixedPath, segs, current, findings)
		if err != nil {
			return "", err
		}
	}

	return current, nil
}

func (p *Pipeline) walkValue(sessionID, parentKey string, segs []pathSeg, val any, findings *[]Finding) (any, error) {
	switch typed := val.(type) {
	case map[string]any:
		for k, v := range typed {
			nextSegs := append(segs, pathSeg{key: k})
			next, err := p.walkValue(sessionID, k, nextSegs, v, findings)
			if err != nil {
				return nil, err
			}
			typed[k] = next
		}
		return typed, nil
	case []any:
		for idx, v := range typed {
			nextSegs := append(segs, pathSeg{index: idx, isIdx: true})
			next, err := p.walkValue(sessionID, parentKey, nextSegs, v, findings)
			if err != nil {
				return nil, err
			}
			typed[idx] = next
		}
		return typed, nil
	case string:
		return p.scrubStringSegs(sessionID, parentKey, "", segs, typed, findings)
	default:
		return val, nil
	}
}

func (p *Pipeline) applyRegexRule(sessionID, fixedPath string, segs []pathSeg, input string, rule *Rule, findings *[]Finding) (string, error) {
	indices := rule.Pattern.FindAllStringIndex(input, -1)
	if len(indices) == 0 {
		return input, nil
	}

	var b strings.Builder
	last := 0
	replaced := false

	for _, idx := range indices {
		start, end := idx[0], idx[1]
		if start < last {
			continue
		}
		if rule.RequiresLeftBoundary && start > 0 && isAlphaNum(input[start-1]) {
			continue
		}
		secret := input[start:end]
		if p.rules.IsAllowlisted(secret) {
			continue
		}

		token, err := p.vault.Store(sessionID, secret)
		if err != nil {
			return "", err
		}

		if !replaced {
			b.Grow(len(input))
			replaced = true
		}
		b.WriteString(input[last:start])
		b.WriteString(token)
		last = end

		fieldPath := fixedPath
		if fieldPath == "" {
			fieldPath = formatPath(segs)
		}
		p.recordFinding(sessionID, rule.ID, token, fieldPath, findings)
	}

	if !replaced {
		return input, nil
	}
	b.WriteString(input[last:])
	return b.String(), nil
}

func (p *Pipeline) applyEntropyRule(sessionID, parentKey, fixedPath string, segs []pathSeg, input string, findings *[]Finding) (string, error) {
	matches := FindHighEntropySecrets(input, parentKey, p.cfg.MinEntropyLength, p.cfg.EntropyThreshold, p.rules)
	if len(matches) == 0 {
		return input, nil
	}

	var b strings.Builder
	b.Grow(len(input))
	last := 0

	for _, m := range matches {
		if m.Start < last {
			continue
		}
		token, err := p.vault.Store(sessionID, m.Secret)
		if err != nil {
			return "", err
		}
		b.WriteString(input[last:m.Start])
		b.WriteString(token)
		last = m.End

		fieldPath := fixedPath
		if fieldPath == "" {
			fieldPath = formatPath(segs)
		}
		p.recordFinding(sessionID, HighEntropyRuleID, token, fieldPath, findings)
	}
	b.WriteString(input[last:])
	return b.String(), nil
}

func (p *Pipeline) recordFinding(sessionID, ruleID, tokenID, fieldPath string, findings *[]Finding) {
	*findings = append(*findings, Finding{
		RuleID:    ruleID,
		TokenID:   tokenID,
		FieldPath: fieldPath,
	})
	if p.audit != nil {
		p.audit.Emit(audit.Event{
			EventType: "secret_redacted",
			SessionID: sessionID,
			RuleID:    ruleID,
			Action:    "tokenize",
			Status:    "redacted",
			TokenID:   tokenID,
			Details: map[string]string{
				"field_path": fieldPath,
			},
		})
	}
}
