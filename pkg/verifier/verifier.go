package verifier

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/legendrail/gitproof-verify/pkg/attestation"
	"github.com/legendrail/gitproof-verify/pkg/gitenv"
	"github.com/legendrail/gitproof-verify/pkg/merklizer"
	"github.com/legendrail/gitproof-verify/pkg/notarize"
)

var (
	ErrMerkleRootMismatch   = errors.New("verifier: computed Merkle root does not match attestation")
	ErrSignatureInvalid     = errors.New("verifier: author signature verification failed")
	ErrTimestampInvalid     = errors.New("verifier: timestamp verification failed")
	ErrCommitMismatch       = errors.New("verifier: repository HEAD does not match attestation commit")
	ErrMissingAttestation   = errors.New("verifier: attestation record is nil")
	ErrMissingPublicKey     = errors.New("verifier: missing public key for verification")
)

// CheckResult represents the outcome of an individual verification gate.
type CheckResult struct {
	Name    string
	Passed  bool
	Message string
}

// VerificationReport contains the complete multi-gate audit trail.
type VerificationReport struct {
	OverallValid bool
	CommitHash   string
	Author       string
	SigningKeyID string
	Timestamp    time.Time
	Checks       []CheckResult
}

// Verifier executes offline mathematical proofs over Git repositories and attestation records.
type Verifier struct {
	GitRunner   gitenv.GitRunner
	SkipTSACheck bool
}

// New returns a Verifier instance.
func New(runner gitenv.GitRunner) *Verifier {
	if runner == nil {
		runner = gitenv.ExecRunner{}
	}
	return &Verifier{
		GitRunner: runner,
	}
}

// VerifyOffline validates that the attestation record mathematically matches the local Git repository state.
func (v *Verifier) VerifyOffline(ctx context.Context, repoRoot string, record *attestation.AttestationRecord, pubKey ed25519.PublicKey) (*VerificationReport, error) {
	if record == nil {
		return nil, ErrMissingAttestation
	}

	report := &VerificationReport{
		OverallValid: true,
		CommitHash:   record.Repository.CommitHash,
		Author:       record.Authorship.AuthorName,
		SigningKeyID: record.Authorship.SigningKeyID,
		Timestamp:    record.Authorship.AuthoredTimestamp,
	}

	// 1. Gate: Verify Ed25519 Author Signature
	sigCheck := CheckResult{Name: "Author Ed25519 Signature"}
	if len(pubKey) == 0 {
		sigCheck.Passed = false
		sigCheck.Message = "public key not provided"
		report.OverallValid = false
		report.Checks = append(report.Checks, sigCheck)
		return report, ErrMissingPublicKey
	}

	valid, err := attestation.VerifyAttestation(record, pubKey)
	if err != nil || !valid {
		sigCheck.Passed = false
		sigCheck.Message = fmt.Sprintf("signature rejected: %v", err)
		report.OverallValid = false
		report.Checks = append(report.Checks, sigCheck)
		return report, ErrSignatureInvalid
	}
	sigCheck.Passed = true
	sigCheck.Message = fmt.Sprintf("signature valid for key %s", record.Authorship.SigningKeyID)
	report.Checks = append(report.Checks, sigCheck)

	// 2. Gate: Local Git Merkle Tree Calculation
	treeCheck := CheckResult{Name: "Git Tree Merkle Integrity"}
	prov, err := merklizer.ComputeTreeProvenance(ctx, v.GitRunner, repoRoot, record.Repository.CommitHash)
	if err != nil {
		treeCheck.Passed = false
		treeCheck.Message = fmt.Sprintf("failed to compute local tree provenance: %v", err)
		report.OverallValid = false
		report.Checks = append(report.Checks, treeCheck)
		return report, fmt.Errorf("verifier: git tree computation failed: %w", err)
	}

	computedOverallHex := merklizer.Bytes32ToHex(prov.OverallMerkleRoot)
	computedTreeHex := merklizer.Bytes32ToHex(prov.TreeMerkleRoot)

	if computedOverallHex != record.Repository.OverallMerkleRoot || computedTreeHex != record.Repository.TreeMerkleRoot {
		treeCheck.Passed = false
		treeCheck.Message = fmt.Sprintf("Merkle root mismatch: expected overall %s, computed %s", record.Repository.OverallMerkleRoot, computedOverallHex)
		report.OverallValid = false
		report.Checks = append(report.Checks, treeCheck)
		return report, ErrMerkleRootMismatch
	}
	treeCheck.Passed = true
	treeCheck.Message = fmt.Sprintf("Merkle root matched: %s", computedOverallHex)
	report.Checks = append(report.Checks, treeCheck)

	// 3. Gate: RFC 3161 Timestamp Verification (if present and not skipped)
	tsCheck := CheckResult{Name: "RFC 3161 Notarization Token"}
	if record.Notarization.RFC3161TokenBase64 != "" && !v.SkipTSACheck {
		tokenDER, err := base64.StdEncoding.DecodeString(record.Notarization.RFC3161TokenBase64)
		if err != nil {
			tsCheck.Passed = false
			tsCheck.Message = fmt.Sprintf("invalid base64 token: %v", err)
			report.OverallValid = false
			report.Checks = append(report.Checks, tsCheck)
			return report, ErrTimestampInvalid
		}

		signingTime, err := notarize.Verify(tokenDER, prov.OverallMerkleRoot[:])
		if err != nil {
			tsCheck.Passed = false
			tsCheck.Message = fmt.Sprintf("timestamp verification rejected: %v", err)
			report.OverallValid = false
			report.Checks = append(report.Checks, tsCheck)
			return report, ErrTimestampInvalid
		}

		tsCheck.Passed = true
		tsCheck.Message = fmt.Sprintf("timestamp verified at %s by %s", signingTime.Format(time.RFC3339), record.Notarization.TSAAuthority)
		report.Timestamp = signingTime
		report.Checks = append(report.Checks, tsCheck)
	} else {
		tsCheck.Passed = true
		tsCheck.Message = "TSA token skipped or unanchored (local-only proof)"
		report.Checks = append(report.Checks, tsCheck)
	}

	return report, nil
}
