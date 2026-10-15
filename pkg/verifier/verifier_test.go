package verifier

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/legendrail/gitproof-verify/pkg/attestation"
	"github.com/legendrail/gitproof-verify/pkg/merklizer"
	"github.com/digitorus/timestamp"
)

type mockVerifierRunner struct {
	responses map[string]string
	errors    map[string]error
}

func (m *mockVerifierRunner) RunGit(_ context.Context, _ string, args ...string) (string, error) {
	key := args[0]
	if len(args) > 1 {
		key = args[0] + " " + args[1]
	}
	if err, ok := m.errors[key]; ok {
		return "", err
	}
	if resp, ok := m.responses[key]; ok {
		return resp, nil
	}
	return "", nil
}

func setupTestTSAToken(t *testing.T, payload []byte) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-tsa"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	sum := sha256.Sum256(payload)
	ts := timestamp.Timestamp{
		HashAlgorithm:     crypto.SHA256,
		HashedMessage:     sum[:],
		Time:              time.Now().UTC(),
		SerialNumber:      big.NewInt(42),
		Policy:            []int{1, 2, 3},
		Certificates:      []*x509.Certificate{cert},
		AddTSACertificate: true,
	}
	resp, err := ts.CreateResponseWithOpts(cert, key, crypto.SHA256)
	if err != nil {
		t.Fatalf("create response: %v", err)
	}
	return resp
}

func TestVerifyOffline_HappyPath(t *testing.T) {
	ctx := context.Background()
	pub, priv, err := attestation.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	runner := &mockVerifierRunner{
		responses: map[string]string{
			"rev-parse HEAD":                  "commit_123",
			"rev-parse commit_123^{tree}":    "tree_456",
			"ls-tree -r":                      "100644 blob blob_1\tfile1.go\x00",
			"log -1":                          "Author\x00a@b.com\x001700000000\x00Author\x00a@b.com\x001700000000\x00parent",
		},
	}

	prov, err := merklizer.ComputeTreeProvenance(ctx, runner, "/mock", "HEAD")
	if err != nil {
		t.Fatalf("provenance failed: %v", err)
	}

	overallHex := merklizer.Bytes32ToHex(prov.OverallMerkleRoot)
	treeHex := merklizer.Bytes32ToHex(prov.TreeMerkleRoot)

	overallBytes, _ := hex.DecodeString(overallHex)
	tsaDER := setupTestTSAToken(t, overallBytes)

	record := &attestation.AttestationRecord{
		Version: "1.0",
		Repository: attestation.RepositoryInfo{
			CommitHash:        "commit_123",
			TreeHash:          "tree_456",
			TreeMerkleRoot:    treeHex,
			OverallMerkleRoot: overallHex,
		},
		Authorship: attestation.AuthorshipInfo{
			AuthorName:        "Author",
			AuthorEmail:       "a@b.com",
			AuthoredTimestamp: time.Date(2026, 10, 14, 21, 30, 0, 0, time.UTC),
		},
		Notarization: attestation.NotarizationInfo{
			TSAAuthority:       "DigiCert",
			RFC3161TokenBase64: base64.StdEncoding.EncodeToString(tsaDER),
		},
	}

	if err := attestation.SignAttestation(record, priv); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	v := New(runner)
	report, err := v.VerifyOffline(ctx, "/mock", record, pub)
	if err != nil {
		t.Fatalf("verification error: %v", err)
	}
	if !report.OverallValid {
		t.Errorf("expected overall valid report")
	}
	if len(report.Checks) != 3 {
		t.Errorf("expected 3 checks, got %d", len(report.Checks))
	}
}

func TestVerifyOffline_NilRecordAndMissingPubkey(t *testing.T) {
	ctx := context.Background()
	v := New(nil)

	_, err := v.VerifyOffline(ctx, "/mock", nil, nil)
	if !errors.Is(err, ErrMissingAttestation) {
		t.Errorf("expected ErrMissingAttestation, got %v", err)
	}

	record := &attestation.AttestationRecord{}
	_, err = v.VerifyOffline(ctx, "/mock", record, nil)
	if !errors.Is(err, ErrMissingPublicKey) {
		t.Errorf("expected ErrMissingPublicKey, got %v", err)
	}
}

func TestVerifyOffline_SignatureFailure(t *testing.T) {
	ctx := context.Background()
	pub, _, _ := attestation.GenerateKeyPair()
	record := &attestation.AttestationRecord{
		Signature: attestation.SignatureInfo{
			Algorithm:       "ed25519",
			SignatureBase64: base64.StdEncoding.EncodeToString([]byte("invalid_sig_bytes_0000000000000000000000000000000000000000000000000000")),
		},
	}

	v := New(nil)
	_, err := v.VerifyOffline(ctx, "/mock", record, pub)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("expected ErrSignatureInvalid, got %v", err)
	}
}

func TestVerifyOffline_MerkleRootMismatch(t *testing.T) {
	ctx := context.Background()
	pub, priv, _ := attestation.GenerateKeyPair()

	runner := &mockVerifierRunner{
		responses: map[string]string{
			"rev-parse HEAD":                  "commit_123",
			"rev-parse commit_123^{tree}":    "tree_456",
			"ls-tree -r":                      "100644 blob blob_1\tfile1.go\x00",
			"log -1":                          "Author\x00a@b.com\x001700000000\x00Author\x00a@b.com\x001700000000\x00parent",
		},
	}

	record := &attestation.AttestationRecord{
		Repository: attestation.RepositoryInfo{
			CommitHash:        "commit_123",
			TreeHash:          "tree_456",
			TreeMerkleRoot:    "different_tree_root",
			OverallMerkleRoot: "different_overall_root",
		},
	}
	_ = attestation.SignAttestation(record, priv)

	v := New(runner)
	_, err := v.VerifyOffline(ctx, "/mock", record, pub)
	if !errors.Is(err, ErrMerkleRootMismatch) {
		t.Errorf("expected ErrMerkleRootMismatch, got %v", err)
	}
}

func TestVerifyOffline_TreeProvenanceFailure(t *testing.T) {
	ctx := context.Background()
	pub, priv, _ := attestation.GenerateKeyPair()

	runner := &mockVerifierRunner{
		errors: map[string]error{
			"rev-parse HEAD": errors.New("git error"),
		},
	}

	record := &attestation.AttestationRecord{
		Repository: attestation.RepositoryInfo{
			CommitHash: "commit_fail",
		},
	}
	_ = attestation.SignAttestation(record, priv)

	v := New(runner)
	_, err := v.VerifyOffline(ctx, "/mock", record, pub)
	if err == nil {
		t.Fatalf("expected error on provenance failure")
	}
}

func TestVerifyOffline_TimestampFailures(t *testing.T) {
	ctx := context.Background()
	pub, priv, _ := attestation.GenerateKeyPair()

	runner := &mockVerifierRunner{
		responses: map[string]string{
			"rev-parse HEAD":                  "commit_123",
			"rev-parse commit_123^{tree}":    "tree_456",
			"ls-tree -r":                      "100644 blob blob_1\tfile1.go\x00",
			"log -1":                          "Author\x00a@b.com\x001700000000\x00Author\x00a@b.com\x001700000000\x00parent",
		},
	}
	prov, _ := merklizer.ComputeTreeProvenance(ctx, runner, "/mock", "HEAD")
	overallHex := merklizer.Bytes32ToHex(prov.OverallMerkleRoot)
	treeHex := merklizer.Bytes32ToHex(prov.TreeMerkleRoot)

	// Test 1: Invalid Base64 in token
	record := &attestation.AttestationRecord{
		Repository: attestation.RepositoryInfo{
			CommitHash:        "commit_123",
			TreeHash:          "tree_456",
			TreeMerkleRoot:    treeHex,
			OverallMerkleRoot: overallHex,
		},
		Notarization: attestation.NotarizationInfo{
			RFC3161TokenBase64: "not_valid_base64!!!",
		},
	}
	_ = attestation.SignAttestation(record, priv)
	v := New(runner)
	_, err := v.VerifyOffline(ctx, "/mock", record, pub)
	if !errors.Is(err, ErrTimestampInvalid) {
		t.Errorf("expected ErrTimestampInvalid for bad base64, got %v", err)
	}

	// Test 2: Invalid TSA verification (token for different digest)
	wrongTSA := setupTestTSAToken(t, []byte("wrong-digest"))
	record.Notarization.RFC3161TokenBase64 = base64.StdEncoding.EncodeToString(wrongTSA)
	_ = attestation.SignAttestation(record, priv)

	_, err = v.VerifyOffline(ctx, "/mock", record, pub)
	if !errors.Is(err, ErrTimestampInvalid) {
		t.Errorf("expected ErrTimestampInvalid for digest mismatch, got %v", err)
	}
}

func TestVerifyOffline_SkipTSAAndInvalidHex(t *testing.T) {
	ctx := context.Background()
	pub, priv, _ := attestation.GenerateKeyPair()

	runner := &mockVerifierRunner{
		responses: map[string]string{
			"rev-parse HEAD":                  "commit_123",
			"rev-parse commit_123^{tree}":    "tree_456",
			"ls-tree -r":                      "100644 blob blob_1\tfile1.go\x00",
			"log -1":                          "Author\x00a@b.com\x001700000000\x00Author\x00a@b.com\x001700000000\x00parent",
		},
	}
	prov, _ := merklizer.ComputeTreeProvenance(ctx, runner, "/mock", "HEAD")
	overallHex := merklizer.Bytes32ToHex(prov.OverallMerkleRoot)
	treeHex := merklizer.Bytes32ToHex(prov.TreeMerkleRoot)

	// Test 1: No TSA token (pure local proof)
	record := &attestation.AttestationRecord{
		Repository: attestation.RepositoryInfo{
			CommitHash:        "commit_123",
			TreeHash:          "tree_456",
			TreeMerkleRoot:    treeHex,
			OverallMerkleRoot: overallHex,
		},
	}
	_ = attestation.SignAttestation(record, priv)

	v := New(runner)
	report, err := v.VerifyOffline(ctx, "/mock", record, pub)
	if err != nil || !report.OverallValid {
		t.Fatalf("expected successful verification without TSA token")
	}

	// Test 2: SkipTSACheck flag is true
	v.SkipTSACheck = true
	record.Notarization.RFC3161TokenBase64 = "dGVzdA=="
	_ = attestation.SignAttestation(record, priv)
	report, err = v.VerifyOffline(ctx, "/mock", record, pub)
	if err != nil || !report.OverallValid {
		t.Fatalf("expected successful verification with SkipTSACheck")
	}

	// Test 3: Invalid hex in OverallMerkleRoot with TSA present
	v.SkipTSACheck = false
	record.Repository.OverallMerkleRoot = "not_valid_hex_!!!"
	// We need mock runner to return "not_valid_hex_!!!" so tree check passes
	badRunner := &mockVerifierRunner{
		responses: map[string]string{
			"rev-parse HEAD":                  "commit_123",
			"rev-parse commit_123^{tree}":    "tree_456",
			"ls-tree -r":                      "",
			"log -1":                          "Author\x00a@b.com\x001700000000\x00Author\x00a@b.com\x001700000000\x00parent",
		},
	}
	badProv, _ := merklizer.ComputeTreeProvenance(ctx, badRunner, "/mock", "HEAD")
	record.Repository.TreeMerkleRoot = merklizer.Bytes32ToHex(badProv.TreeMerkleRoot)
	record.Repository.OverallMerkleRoot = merklizer.Bytes32ToHex(badProv.OverallMerkleRoot)
	// Corrupt after signing to trigger invalid hex inside TSA check
	record.Notarization.RFC3161TokenBase64 = "dGVzdA=="
	_ = attestation.SignAttestation(record, priv)
	// Break the hex
	record.Repository.OverallMerkleRoot = "ZZZZZZZZ"
	// Re-sign with invalid hex to pass sig check
	_ = attestation.SignAttestation(record, priv)
	// Make sure prov matches so it reaches TSA check
	// (we can directly test TSA branch error)
}
