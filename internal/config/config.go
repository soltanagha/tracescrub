package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const tokenAllowlistPattern = `^__TS_TOK_[a-f0-9]{8}__$`

// Config defines the complete TraceScrub configuration schema.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Upstream UpstreamConfig `yaml:"upstream"`
	Security SecurityConfig `yaml:"security"`
	Audit    AuditConfig    `yaml:"audit"`
}

// ServerConfig configures the proxy listener, admin API listener, and limits.
type ServerConfig struct {
	ListenAddr    string `yaml:"listen_addr"`
	AdminAddr     string `yaml:"admin_addr"`
	ReadTimeoutMs int    `yaml:"read_timeout_ms"`
	MaxBodyBytes  int64  `yaml:"max_body_bytes"`
}

// UpstreamConfig configures upstream LLM endpoints and routing prefixes.
type UpstreamConfig struct {
	DefaultTarget string            `yaml:"default_target"`
	Routes        map[string]string `yaml:"routes"`
	TimeoutMs     int               `yaml:"timeout_ms"`
}

// SecurityConfig configures fail-closed enforcement, vault TTL, and redaction rules.
type SecurityConfig struct {
	StrictMode          bool               `yaml:"strict_mode"`
	DetokenizeResponses bool               `yaml:"detokenize_responses"`
	VaultTTLSeconds     int                `yaml:"vault_ttl_seconds"`
	EntropyThreshold    float64            `yaml:"entropy_threshold"`
	MinEntropyLength    int                `yaml:"min_entropy_length"`
	AllowlistPatterns   []string           `yaml:"allowlist_patterns"`
	CustomRules         []CustomRuleConfig `yaml:"custom_rules"`
}

// CustomRuleConfig defines an organization-specific regex secret rule.
type CustomRuleConfig struct {
	ID                string `yaml:"id"`
	Pattern           string `yaml:"pattern"`
	ReplacementPrefix string `yaml:"replacement_prefix"`
}

// AuditConfig configures structured JSONL audit logging.
type AuditConfig struct {
	Enabled           bool   `yaml:"enabled"`
	OutputPath        string `yaml:"output_path"`
	IncludeRawSecrets bool   `yaml:"include_raw_secrets"`
}

// Default returns a Config populated with production-safe defaults.
func Default() *Config {
	return &Config{
		Server: ServerConfig{
			ListenAddr:    "127.0.0.1:8443",
			AdminAddr:     "127.0.0.1:9090",
			ReadTimeoutMs: 5000,
			MaxBodyBytes:  10485760,
		},
		Upstream: UpstreamConfig{
			DefaultTarget: "https://api.openai.com",
			Routes:        map[string]string{},
			TimeoutMs:     60000,
		},
		Security: SecurityConfig{
			StrictMode:          true,
			DetokenizeResponses: true,
			VaultTTLSeconds:     900,
			EntropyThreshold:    4.5,
			MinEntropyLength:    20,
			AllowlistPatterns:   []string{tokenAllowlistPattern},
		},
		Audit: AuditConfig{
			Enabled:           true,
			OutputPath:        "./tracescrub-audit.jsonl",
			IncludeRawSecrets: false,
		},
	}
}

// Load reads, applies defaults to, and validates a YAML configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	return Parse(data)
}

// Parse unmarshals YAML bytes into a validated Config with defaults applied.
func Parse(data []byte) (*Config, error) {
	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse yaml config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	def := Default()
	if strings.TrimSpace(c.Server.ListenAddr) == "" {
		c.Server.ListenAddr = def.Server.ListenAddr
	}
	if strings.TrimSpace(c.Server.AdminAddr) == "" {
		c.Server.AdminAddr = def.Server.AdminAddr
	}
	if c.Server.ReadTimeoutMs <= 0 {
		c.Server.ReadTimeoutMs = def.Server.ReadTimeoutMs
	}
	if c.Server.MaxBodyBytes <= 0 {
		c.Server.MaxBodyBytes = def.Server.MaxBodyBytes
	}
	if strings.TrimSpace(c.Upstream.DefaultTarget) == "" {
		c.Upstream.DefaultTarget = def.Upstream.DefaultTarget
	}
	if c.Upstream.Routes == nil {
		c.Upstream.Routes = map[string]string{}
	}
	if c.Upstream.TimeoutMs <= 0 {
		c.Upstream.TimeoutMs = def.Upstream.TimeoutMs
	}
	if c.Security.VaultTTLSeconds <= 0 {
		c.Security.VaultTTLSeconds = def.Security.VaultTTLSeconds
	}
	if c.Security.EntropyThreshold <= 0 {
		c.Security.EntropyThreshold = def.Security.EntropyThreshold
	}
	if c.Security.MinEntropyLength <= 0 {
		c.Security.MinEntropyLength = def.Security.MinEntropyLength
	}
	if !slices.Contains(c.Security.AllowlistPatterns, tokenAllowlistPattern) {
		c.Security.AllowlistPatterns = append([]string{tokenAllowlistPattern}, c.Security.AllowlistPatterns...)
	}
	if c.Audit.Enabled && strings.TrimSpace(c.Audit.OutputPath) == "" {
		c.Audit.OutputPath = def.Audit.OutputPath
	}
}

// Validate verifies all security and operational invariants on the configuration.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config cannot be nil")
	}
	if c.Audit.IncludeRawSecrets {
		return errors.New("security violation: audit.include_raw_secrets is hard-enforced false and cannot be enabled")
	}
	if _, _, err := net.SplitHostPort(c.Server.ListenAddr); err != nil {
		return fmt.Errorf("invalid server.listen_addr %q: %w", c.Server.ListenAddr, err)
	}
	if err := validateLoopbackAddr(c.Server.AdminAddr); err != nil {
		return fmt.Errorf("invalid server.admin_addr %q: %w", c.Server.AdminAddr, err)
	}
	if c.Server.MaxBodyBytes <= 0 {
		return errors.New("server.max_body_bytes must be positive")
	}
	if c.Server.ReadTimeoutMs <= 0 {
		return errors.New("server.read_timeout_ms must be positive")
	}
	if c.Upstream.TimeoutMs <= 0 {
		return errors.New("upstream.timeout_ms must be positive")
	}
	if err := validateTargetURL(c.Upstream.DefaultTarget); err != nil {
		return fmt.Errorf("invalid upstream.default_target: %w", err)
	}
	for prefix, target := range c.Upstream.Routes {
		if strings.TrimSpace(prefix) == "" {
			return errors.New("upstream.routes prefix cannot be empty")
		}
		if err := validateTargetURL(target); err != nil {
			return fmt.Errorf("invalid upstream.routes[%q]: %w", prefix, err)
		}
	}
	if c.Security.VaultTTLSeconds <= 0 {
		return errors.New("security.vault_ttl_seconds must be positive")
	}
	if c.Security.EntropyThreshold <= 0 {
		return errors.New("security.entropy_threshold must be positive")
	}
	if c.Security.MinEntropyLength <= 0 {
		return errors.New("security.min_entropy_length must be positive")
	}
	for i, pat := range c.Security.AllowlistPatterns {
		if _, err := regexp.Compile(pat); err != nil {
			return fmt.Errorf("invalid security.allowlist_patterns[%d] %q: %w", i, pat, err)
		}
	}
	seenIDs := make(map[string]struct{}, len(c.Security.CustomRules))
	for i, rule := range c.Security.CustomRules {
		if strings.TrimSpace(rule.ID) == "" {
			return fmt.Errorf("security.custom_rules[%d].id cannot be empty", i)
		}
		if _, exists := seenIDs[rule.ID]; exists {
			return fmt.Errorf("duplicate security.custom_rules id %q", rule.ID)
		}
		seenIDs[rule.ID] = struct{}{}
		if strings.TrimSpace(rule.Pattern) == "" {
			return fmt.Errorf("security.custom_rules[%d].pattern cannot be empty", i)
		}
		if _, err := regexp.Compile(rule.Pattern); err != nil {
			return fmt.Errorf("invalid security.custom_rules[%d].pattern %q: %w", i, rule.Pattern, err)
		}
	}
	return nil
}

// ReadTimeout returns the configured HTTP server read timeout duration.
func (c *Config) ReadTimeout() time.Duration {
	return time.Duration(c.Server.ReadTimeoutMs) * time.Millisecond
}

// UpstreamTimeout returns the configured upstream HTTP client timeout duration.
func (c *Config) UpstreamTimeout() time.Duration {
	return time.Duration(c.Upstream.TimeoutMs) * time.Millisecond
}

// VaultTTL returns the configured ephemeral token TTL duration.
func (c *Config) VaultTTL() time.Duration {
	return time.Duration(c.Security.VaultTTLSeconds) * time.Second
}

func validateLoopbackAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("admin_addr must bind strictly to loopback (127.0.0.1, ::1, or localhost)")
	}
	return nil
}

func validateTargetURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported scheme %q (must be http or https)", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("target URL must include host")
	}
	return nil
}
