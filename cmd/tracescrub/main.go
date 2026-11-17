package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/tracescrub/tracescrub/internal/audit"
	"github.com/tracescrub/tracescrub/internal/config"
	"github.com/tracescrub/tracescrub/internal/extpin"
	"github.com/tracescrub/tracescrub/internal/proxy"
	"github.com/tracescrub/tracescrub/internal/redact"
	"github.com/tracescrub/tracescrub/internal/vault"
)

const versionString = "1.0.0"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		printUsage()
		return 1
	}

	switch args[0] {
	case "serve":
		return runServe(args[1:])
	case "ext":
		return runExt(args[1:])
	case "version", "--version", "-v":
		fmt.Printf("tracescrub %s\n", versionString)
		return 0
	case "help", "--help", "-h":
		printUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", args[0])
		printUsage()
		return 1
	}
}

func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs.String("config", "./configs/config.example.yaml", "Path to YAML configuration file")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		return 1
	}

	v, err := vault.New(cfg.VaultTTL())
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize ephemeral vault: %v\n", err)
		return 1
	}
	defer v.Close()

	auditLogger, err := audit.New(cfg.Audit.Enabled, cfg.Audit.OutputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize audit logger: %v\n", err)
		return 1
	}
	defer auditLogger.Close()

	pipeline, err := redact.NewPipeline(cfg.Security, v, auditLogger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize redaction pipeline: %v\n", err)
		return 1
	}

	srv, err := proxy.NewServer(cfg, v, pipeline, auditLogger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize proxy server: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "tracescrub %s listening: proxy=%s admin=%s\n", versionString, cfg.Server.ListenAddr, cfg.Server.AdminAddr)
	if err := srv.ListenAndServe(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		return 1
	}
	return 0
}

func runExt(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: tracescrub ext <verify|pin> [flags]")
		return 2
	}
	switch args[0] {
	case "verify":
		return runExtVerify(args[1:])
	case "pin":
		return runExtPin(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown ext subcommand %q\n", args[0])
		return 2
	}
}

func runExtVerify(args []string) int {
	fs := flag.NewFlagSet("ext verify", flag.ContinueOnError)
	filePath := fs.String("file", "", "Path to VSIX or tarball artifact")
	sigPath := fs.String("sig", "", "Path to detached Ed25519 signature (defaults to <file>.sig)")
	publisher := fs.String("publisher", "", "Publisher ID")
	extensionID := fs.String("extension", "", "Extension ID (inferred if publisher allows exactly one extension)")
	version := fs.String("version", "", "Artifact version")
	policyPath := fs.String("policy", "./configs/trust-policy.example.json", "Path to trust-policy.json")
	auditPath := fs.String("audit-log", "", "Optional path to JSONL audit log")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	var auditLogger *audit.Logger
	if *auditPath != "" {
		var err error
		auditLogger, err = audit.New(true, *auditPath)
		if err != nil {
			emitJSONError("audit_init_failed", err.Error())
			return 1
		}
		defer auditLogger.Close()
	}

	policy, err := extpin.LoadPolicy(*policyPath)
	if err != nil {
		res := extpin.VerifyResult{
			Allowed:         false,
			Publisher:       *publisher,
			Extension:       *extensionID,
			Version:         *version,
			File:            *filePath,
			ViolationCode:   "policy_load_error",
			ViolationReason: err.Error(),
		}
		printVerifyResult(res)
		return 1
	}

	res := extpin.Verify(policy, extpin.VerifyRequest{
		FilePath:    *filePath,
		SigPath:     *sigPath,
		Publisher:   *publisher,
		ExtensionID: *extensionID,
		Version:     *version,
	}, auditLogger)

	printVerifyResult(res)
	if !res.Allowed {
		return 1
	}
	return 0
}

func runExtPin(args []string) int {
	fs := flag.NewFlagSet("ext pin", flag.ContinueOnError)
	filePath := fs.String("file", "", "Path to VSIX or tarball artifact")
	publisher := fs.String("publisher", "", "Publisher ID")
	extensionID := fs.String("extension", "", "Extension ID")
	version := fs.String("version", "", "Artifact version")
	policyPath := fs.String("policy", "./trust-policy.json", "Path to trust-policy.json")
	pubKeyHex := fs.String("pubkey-hex", "", "Optional 64-char hex Ed25519 public key")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	var policy *extpin.TrustPolicy
	if _, err := os.Stat(*policyPath); err == nil {
		policy, err = extpin.LoadPolicy(*policyPath)
		if err != nil {
			emitJSONError("policy_load_error", err.Error())
			return 1
		}
	} else {
		policy = &extpin.TrustPolicy{
			Version:          "1",
			RequireSignature: true,
			Publishers:       map[string]extpin.PublisherTrust{},
			PinnedArtifacts:  map[string]extpin.PinnedArtifact{},
		}
	}

	digest, err := extpin.PinArtifact(policy, *publisher, *extensionID, *version, *filePath, *pubKeyHex)
	if err != nil {
		emitJSONError("pin_failed", err.Error())
		return 1
	}
	if err := extpin.SavePolicy(*policyPath, policy); err != nil {
		emitJSONError("policy_save_error", err.Error())
		return 1
	}

	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{
		"status":    "pinned",
		"publisher": *publisher,
		"extension": *extensionID,
		"version":   *version,
		"sha256":    digest,
		"policy":    *policyPath,
	})
	return 0
}

func printVerifyResult(res extpin.VerifyResult) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
}

func emitJSONError(code, msg string) {
	_ = json.NewEncoder(os.Stderr).Encode(map[string]string{
		"violation_code":   code,
		"violation_reason": msg,
	})
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `TraceScrub - Zero-Trust Agent Egress Proxy & Extension Pinning CLI

Usage:
  tracescrub serve --config <path.yaml>
  tracescrub ext verify --file <path.vsix> --publisher <id> --version <ver> [--extension <id>] [--policy <path>] [--sig <path>] [--audit-log <path>]
  tracescrub ext pin --file <path.vsix> --publisher <id> --extension <id> --version <ver> [--policy <path>] [--pubkey-hex <hex>]
  tracescrub version`)
}
