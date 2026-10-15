package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/legendrail/gitproof-verify/pkg/attestation"
	"github.com/legendrail/gitproof-verify/pkg/gitenv"
	"github.com/legendrail/gitproof-verify/pkg/verifier"
)

var (
	Version   = "v0.1.0"
	GitCommit = "HEAD"
)

func main() {
	exitCode := Run(os.Args[1:], os.Stdout, os.Stderr, nil)
	os.Exit(exitCode)
}

// Run executes the verification CLI.
func Run(args []string, stdout, stderr io.Writer, runner gitenv.GitRunner) int {
	fs := flag.NewFlagSet("gproof-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		repoDir   string
		proofPath string
		pubKeyHex string
		skipTSA   bool
		showHelp  bool
		showVer   bool
	)

	fs.StringVar(&repoDir, "dir", ".", "Path to git repository root")
	fs.StringVar(&proofPath, "proof", "", "Path to proof.json (defaults to <dir>/.gitproof/proof.json)")
	fs.StringVar(&pubKeyHex, "key", "", "Author Ed25519 public key in hex (defaults to key in proof.json)")
	fs.BoolVar(&skipTSA, "skip-tsa", false, "Skip RFC 3161 timestamp authority check")
	fs.BoolVar(&showHelp, "help", false, "Show help message")
	fs.BoolVar(&showVer, "version", false, "Show verifier version")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	if showVer {
		fmt.Fprintf(stdout, "gproof-verify %s (%s)\n", Version, GitCommit)
		return 0
	}

	if showHelp {
		fs.Usage()
		return 0
	}

	if proofPath == "" {
		proofPath = filepath.Join(repoDir, ".gitproof", "proof.json")
	}

	data, err := os.ReadFile(proofPath)
	if err != nil {
		fmt.Fprintf(stderr, "❌ Error reading proof file: %v\n", err)
		return 1
	}

	var record attestation.AttestationRecord
	if err := json.Unmarshal(data, &record); err != nil {
		fmt.Fprintf(stderr, "❌ Error parsing proof.json: %v\n", err)
		return 1
	}

	var pubKey ed25519.PublicKey
	if pubKeyHex != "" {
		pubKeyBytes, err := hex.DecodeString(pubKeyHex)
		if err != nil {
			fmt.Fprintf(stderr, "❌ Invalid hex public key: %v\n", err)
			return 1
		}
		pubKey = pubKeyBytes
	} else {
		keyPath := filepath.Join(repoDir, ".gitproof", "key.pub")
		if keyData, err := os.ReadFile(keyPath); err == nil {
			pubKeyBytes, err := hex.DecodeString(strings.TrimSpace(string(keyData)))
			if err == nil && len(pubKeyBytes) == ed25519.PublicKeySize {
				pubKey = pubKeyBytes
			}
		}
	}

	v := verifier.New(runner)
	v.SkipTSACheck = skipTSA

	report, err := v.VerifyOffline(context.Background(), repoDir, &record, pubKey)
	if err != nil && report == nil {
		fmt.Fprintf(stderr, "❌ Verification failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "🔍 GitProof Independent Verifier\n")
	fmt.Fprintf(stdout, "Commit:    %s\n", report.CommitHash)
	fmt.Fprintf(stdout, "Author:    %s\n", report.Author)
	fmt.Fprintf(stdout, "Timestamp: %s\n\n", report.Timestamp.Format("2006-01-02 15:04:05 MST"))

	for _, check := range report.Checks {
		if check.Passed {
			fmt.Fprintf(stdout, "  ✅ %-30s [PASS] %s\n", check.Name, check.Message)
		} else {
			fmt.Fprintf(stdout, "  ❌ %-30s [FAIL] %s\n", check.Name, check.Message)
		}
	}

	if !report.OverallValid {
		fmt.Fprintf(stderr, "\n❌ VERIFICATION FAILED: Record does not mathematically authenticate repository state.\n")
		return 1
	}

	fmt.Fprintf(stdout, "\n🛡️ VERIFICATION SUCCESSFUL: Provenance and RFC 3161 timestamp mathematically authenticated.\n")
	return 0
}
