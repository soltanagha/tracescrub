package extpin

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/tracescrub/tracescrub/internal/audit"
)

// QA-07: Extension pinning unit validation across valid, revoked, tampered, and bad-sig artifacts.
func TestQA07_VerifyExtensionArtifacts(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 keypair: %v", err)
	}

	dir := t.TempDir()
	validBytes := []byte("PK\x03\x04mock-vsix-payload-for-anthropic-claude-code-2.1.314")
	validSum := sha256.Sum256(validBytes)
	validSHA := hex.EncodeToString(validSum[:])

	revokedBytes := []byte("PK\x03\x04mock-vsix-payload-for-anthropic-claude-code-2.1.312")
	revokedSum := sha256.Sum256(revokedBytes)
	revokedSHA := hex.EncodeToString(revokedSum[:])

	policy := &TrustPolicy{
		Version:          "1",
		RequireSignature: true,
		Publishers: map[string]PublisherTrust{
			"anthropic": {
				Ed25519PublicKeyHex: hex.EncodeToString(pub),
				AllowedExtensions:   []string{"anthropic.claude-code"},
			},
		},
		PinnedArtifacts: map[string]PinnedArtifact{
			"anthropic.claude-code": {
				MinVersion:      "2.1.314",
				RevokedVersions: []string{"2.1.312", "2.1.313"},
				SHA256ByVersion: map[string]string{
					"2.1.312": revokedSHA,
					"2.1.314": validSHA,
				},
			},
		},
	}

	validFile := filepath.Join(dir, "claude-code-2.1.314.vsix")
	if err := os.WriteFile(validFile, validBytes, 0o600); err != nil {
		t.Fatalf("write valid vsix: %v", err)
	}
	validSig := ed25519.Sign(priv, validBytes)
	if err := os.WriteFile(validFile+".sig", []byte(hex.EncodeToString(validSig)), 0o600); err != nil {
		t.Fatalf("write valid sig: %v", err)
	}

	revokedFile := filepath.Join(dir, "claude-code-2.1.312.vsix")
	if err := os.WriteFile(revokedFile, revokedBytes, 0o600); err != nil {
		t.Fatalf("write revoked vsix: %v", err)
	}
	revokedSig := ed25519.Sign(priv, revokedBytes)
	if err := os.WriteFile(revokedFile+".sig", []byte(hex.EncodeToString(revokedSig)), 0o600); err != nil {
		t.Fatalf("write revoked sig: %v", err)
	}

	tamperedFile := filepath.Join(dir, "claude-code-tampered.vsix")
	tamperedBytes := append([]byte(nil), validBytes...)
	tamperedBytes[len(tamperedBytes)-1] ^= 0x01 // 1-byte flip
	if err := os.WriteFile(tamperedFile, tamperedBytes, 0o600); err != nil {
		t.Fatalf("write tampered vsix: %v", err)
	}
	if err := os.WriteFile(tamperedFile+".sig", []byte(hex.EncodeToString(validSig)), 0o600); err != nil {
		t.Fatalf("write tampered sig: %v", err)
	}

	badSigFile := filepath.Join(dir, "claude-code-badsig.vsix")
	if err := os.WriteFile(badSigFile, validBytes, 0o600); err != nil {
		t.Fatalf("write badsig vsix: %v", err)
	}
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrongSig := ed25519.Sign(otherPriv, validBytes)
	if err := os.WriteFile(badSigFile+".sig", []byte(hex.EncodeToString(wrongSig)), 0o600); err != nil {
		t.Fatalf("write wrong sig: %v", err)
	}

	auditPath := filepath.Join(dir, "audit.jsonl")
	al, err := audit.New(true, auditPath)
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	defer al.Close()

	// (a) Valid signed VSIX -> allowed
	resA := Verify(policy, VerifyRequest{
		FilePath:  validFile,
		Publisher: "anthropic",
		Version:   "2.1.314",
	}, al)
	if !resA.Allowed || resA.ViolationCode != "" {
		t.Fatalf("(a) expected allowed=true, got: %+v", resA)
	}

	// (b) Revoked version 2.1.312 -> blocked
	resB := Verify(policy, VerifyRequest{
		FilePath:  revokedFile,
		Publisher: "anthropic",
		Version:   "2.1.312",
	}, al)
	if resB.Allowed || resB.ViolationCode != "version_revoked" {
		t.Fatalf("(b) expected violation version_revoked, got: %+v", resB)
	}

	// (c) Tampered VSIX (1-byte flip) -> blocked
	resC := Verify(policy, VerifyRequest{
		FilePath:  tamperedFile,
		Publisher: "anthropic",
		Version:   "2.1.314",
	}, al)
	if resC.Allowed || resC.ViolationCode != "sha256_mismatch" {
		t.Fatalf("(c) expected violation sha256_mismatch, got: %+v", resC)
	}

	// (d) Invalid Ed25519 signature -> blocked
	resD := Verify(policy, VerifyRequest{
		FilePath:  badSigFile,
		Publisher: "anthropic",
		Version:   "2.1.314",
	}, al)
	if resD.Allowed || resD.ViolationCode != "invalid_signature" {
		t.Fatalf("(d) expected violation invalid_signature, got: %+v", resD)
	}
}
