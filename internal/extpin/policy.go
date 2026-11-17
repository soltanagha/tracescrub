package extpin

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/tracescrub/tracescrub/internal/audit"
)

// TrustPolicy models the immutable extension verification policy (trust-policy.json).
type TrustPolicy struct {
	Version          string                    `json:"version"`
	RequireSignature bool                      `json:"require_signature"`
	Publishers       map[string]PublisherTrust `json:"publishers"`
	PinnedArtifacts  map[string]PinnedArtifact `json:"pinned_artifacts"`
}

// PublisherTrust identifies a trusted publisher's Ed25519 public key and allowed extension IDs.
type PublisherTrust struct {
	Ed25519PublicKeyHex string   `json:"ed25519_public_key_hex"`
	AllowedExtensions   []string `json:"allowed_extensions"`
}

// PinnedArtifact defines version constraints, revocations, and pinned SHA-256 digests.
type PinnedArtifact struct {
	MinVersion      string            `json:"min_version"`
	RevokedVersions []string          `json:"revoked_versions"`
	SHA256ByVersion map[string]string `json:"sha256_by_version"`
}

// VerifyRequest supplies inputs for pre-install extension verification.
type VerifyRequest struct {
	FilePath    string
	SigPath     string
	Publisher   string
	ExtensionID string
	Version     string
}

// VerifyResult describes the structured security decision emitted by Verify.
type VerifyResult struct {
	Allowed         bool   `json:"allowed"`
	Publisher       string `json:"publisher"`
	Extension       string `json:"extension"`
	Version         string `json:"version"`
	File            string `json:"file"`
	SHA256          string `json:"sha256,omitempty"`
	ViolationCode   string `json:"violation_code,omitempty"`
	ViolationReason string `json:"violation_reason,omitempty"`
}

// LoadPolicy loads and validates a trust-policy.json file.
func LoadPolicy(path string) (*TrustPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("extpin: read policy %q: %w", path, err)
	}
	var policy TrustPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("extpin: parse policy %q: %w", path, err)
	}
	if policy.Publishers == nil {
		policy.Publishers = map[string]PublisherTrust{}
	}
	if policy.PinnedArtifacts == nil {
		policy.PinnedArtifacts = map[string]PinnedArtifact{}
	}
	return &policy, nil
}

// SavePolicy writes the TrustPolicy back to disk formatted as indented JSON.
func SavePolicy(path string, policy *TrustPolicy) error {
	if policy == nil {
		return errors.New("extpin: policy cannot be nil")
	}
	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return fmt.Errorf("extpin: marshal policy: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("extpin: write policy %q: %w", path, err)
	}
	return nil
}

// Verify validates an extension archive's SHA-256 digest, version constraints,
// revocation status, and detached Ed25519 signature (over the raw archive bytes).
func Verify(policy *TrustPolicy, req VerifyRequest, auditLogger *audit.Logger) VerifyResult {
	res := VerifyResult{
		Allowed:   false,
		Publisher: strings.TrimSpace(req.Publisher),
		Extension: strings.TrimSpace(req.ExtensionID),
		Version:   strings.TrimSpace(req.Version),
		File:      req.FilePath,
	}

	fail := func(code, reason string) VerifyResult {
		res.Allowed = false
		res.ViolationCode = code
		res.ViolationReason = reason
		emitVerifyAudit(auditLogger, res)
		return res
	}

	if policy == nil {
		return fail("policy_missing", "trust policy is nil")
	}
	if res.Publisher == "" || res.Version == "" || res.File == "" {
		return fail("invalid_arguments", "file, publisher, and version are required")
	}

	pub, ok := policy.Publishers[res.Publisher]
	if !ok {
		return fail("unknown_publisher", fmt.Sprintf("publisher %q is not trusted in policy", res.Publisher))
	}

	if res.Extension == "" {
		if len(pub.AllowedExtensions) == 1 {
			res.Extension = pub.AllowedExtensions[0]
		} else {
			return fail("extension_required", fmt.Sprintf("extension id required for publisher %q", res.Publisher))
		}
	}

	if !slices.Contains(pub.AllowedExtensions, res.Extension) {
		return fail("extension_not_allowed", fmt.Sprintf("extension %q is not allowed for publisher %q", res.Extension, res.Publisher))
	}

	artifact, ok := policy.PinnedArtifacts[res.Extension]
	if !ok {
		return fail("extension_not_pinned", fmt.Sprintf("extension %q has no pinned artifact entry", res.Extension))
	}

	if slices.Contains(artifact.RevokedVersions, res.Version) {
		return fail("version_revoked", fmt.Sprintf("version %s of %s is explicitly revoked", res.Version, res.Extension))
	}

	if artifact.MinVersion != "" {
		cmp, err := compareSemver(res.Version, artifact.MinVersion)
		if err != nil {
			return fail("invalid_version", fmt.Sprintf("invalid semver comparison (%s vs %s): %v", res.Version, artifact.MinVersion, err))
		}
		if cmp < 0 {
			return fail("version_below_minimum", fmt.Sprintf("version %s is below minimum pinned version %s", res.Version, artifact.MinVersion))
		}
	}

	archiveBytes, err := os.ReadFile(req.FilePath)
	if err != nil {
		return fail("file_read_error", fmt.Sprintf("failed to read extension file %q: %v", req.FilePath, err))
	}

	sum := sha256.Sum256(archiveBytes)
	actualSHA := hex.EncodeToString(sum[:])
	res.SHA256 = actualSHA

	expectedSHA, ok := artifact.SHA256ByVersion[res.Version]
	if !ok || strings.TrimSpace(expectedSHA) == "" {
		return fail("unpinned_version", fmt.Sprintf("version %s of %s has no pinned sha256 digest", res.Version, res.Extension))
	}
	if !strings.EqualFold(actualSHA, strings.TrimSpace(expectedSHA)) {
		return fail("sha256_mismatch", fmt.Sprintf("sha256 mismatch: expected %s, got %s", expectedSHA, actualSHA))
	}

	if policy.RequireSignature {
		pubKeyBytes, err := hex.DecodeString(strings.TrimSpace(pub.Ed25519PublicKeyHex))
		if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
			return fail("invalid_public_key", fmt.Sprintf("invalid ed25519 public key for publisher %q", res.Publisher))
		}

		sigPath := req.SigPath
		if sigPath == "" {
			sigPath = req.FilePath + ".sig"
		}
		sigRaw, err := os.ReadFile(sigPath)
		if err != nil {
			return fail("signature_missing", fmt.Sprintf("failed to read detached signature %q: %v", sigPath, err))
		}
		sigBytes, err := decodeSignature(sigRaw)
		if err != nil {
			return fail("invalid_signature_encoding", fmt.Sprintf("invalid ed25519 signature encoding in %q: %v", sigPath, err))
		}
		if !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), archiveBytes, sigBytes) {
			return fail("invalid_signature", fmt.Sprintf("ed25519 signature verification failed for %s@%s", res.Extension, res.Version))
		}
	}

	res.Allowed = true
	emitVerifyAudit(auditLogger, res)
	return res
}

// PinArtifact computes the SHA-256 digest of filePath and updates policy with the pinned digest.
func PinArtifact(policy *TrustPolicy, publisher, extensionID, version, filePath, pubKeyHex string) (string, error) {
	if policy == nil {
		return "", errors.New("extpin: policy cannot be nil")
	}
	if publisher == "" || extensionID == "" || version == "" || filePath == "" {
		return "", errors.New("extpin: publisher, extension, version, and file are required")
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("extpin: read artifact %q: %w", filePath, err)
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])

	if policy.Version == "" {
		policy.Version = "1"
	}
	if policy.Publishers == nil {
		policy.Publishers = map[string]PublisherTrust{}
	}
	if policy.PinnedArtifacts == nil {
		policy.PinnedArtifacts = map[string]PinnedArtifact{}
	}

	pub := policy.Publishers[publisher]
	if pubKeyHex != "" {
		pub.Ed25519PublicKeyHex = pubKeyHex
	}
	if !slices.Contains(pub.AllowedExtensions, extensionID) {
		pub.AllowedExtensions = append(pub.AllowedExtensions, extensionID)
	}
	policy.Publishers[publisher] = pub

	art := policy.PinnedArtifacts[extensionID]
	if art.MinVersion == "" {
		art.MinVersion = version
	}
	if art.SHA256ByVersion == nil {
		art.SHA256ByVersion = map[string]string{}
	}
	art.SHA256ByVersion[version] = digest
	policy.PinnedArtifacts[extensionID] = art

	return digest, nil
}

func emitVerifyAudit(auditLogger *audit.Logger, res VerifyResult) {
	if auditLogger == nil {
		return
	}
	status := "allowed"
	ruleID := "extpin-verified"
	if !res.Allowed {
		status = "blocked"
		ruleID = "extpin-" + res.ViolationCode
	}
	details := map[string]string{
		"publisher": res.Publisher,
		"extension": res.Extension,
		"version":   res.Version,
	}
	if res.SHA256 != "" {
		details["sha256"] = res.SHA256
	}
	if res.ViolationReason != "" {
		details["reason"] = res.ViolationReason
	}
	auditLogger.Emit(audit.Event{
		EventType: "extension_verify",
		RuleID:    ruleID,
		Action:    "verify",
		Status:    status,
		Details:   details,
	})
}

func decodeSignature(raw []byte) ([]byte, error) {
	if len(raw) == ed25519.SignatureSize {
		return raw, nil
	}
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == ed25519.SignatureSize*2 {
		b, err := hex.DecodeString(trimmed)
		if err == nil && len(b) == ed25519.SignatureSize {
			return b, nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(b) == ed25519.SignatureSize {
		return b, nil
	}
	return nil, fmt.Errorf("expected %d-byte raw, hex, or base64 Ed25519 signature", ed25519.SignatureSize)
}

func compareSemver(a, b string) (int, error) {
	pa, err := parseSemverParts(a)
	if err != nil {
		return 0, err
	}
	pb, err := parseSemverParts(b)
	if err != nil {
		return 0, err
	}
	for i := 0; i < 3; i++ {
		if pa[i] < pb[i] {
			return -1, nil
		}
		if pa[i] > pb[i] {
			return 1, nil
		}
	}
	return 0, nil
}

func parseSemverParts(v string) ([3]int, error) {
	var out [3]int
	clean := strings.TrimPrefix(strings.TrimSpace(v), "v")
	if idx := strings.IndexAny(clean, "-+"); idx >= 0 {
		clean = clean[:idx]
	}
	parts := strings.Split(clean, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return out, fmt.Errorf("invalid version %q", v)
	}
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return out, fmt.Errorf("invalid numeric version segment %q in %q", part, v)
		}
		out[i] = n
	}
	return out, nil
}
