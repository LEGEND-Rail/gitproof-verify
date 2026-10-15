package attestation

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func TestCanonicalize_KeySorting(t *testing.T) {
	input := map[string]any{
		"zebra": "stripes",
		"apple": 1,
		"beta":  true,
		"nested": map[string]any{
			"z": 100,
			"a": 50,
		},
	}

	canonical, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := `{"apple":1,"beta":true,"nested":{"a":50,"z":100},"zebra":"stripes"}`
	if string(canonical) != expected {
		t.Errorf("expected %s, got %s", expected, string(canonical))
	}
}

func TestCanonicalize_ArrayAndNull(t *testing.T) {
	input := []any{nil, false, "hello", 42.5}
	canonical, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := `[null,false,"hello",42.5]`
	if string(canonical) != expected {
		t.Errorf("expected %s, got %s", expected, string(canonical))
	}
}

func TestSignAndVerifyAttestation_HappyPath(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed keygen: %v", err)
	}

	record := &AttestationRecord{
		Version: "1.0",
		Repository: RepositoryInfo{
			OriginURL:         "git@github.com:LEGEND-Rail/gitproof.git",
			Branch:            "main",
			CommitHash:        "1111222233334444555566667777888899990000",
			TreeHash:          "aaaabbbbccccddddeeeeffff0000111122223333",
			TreeMerkleRoot:    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			OverallMerkleRoot: "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe",
		},
		Authorship: AuthorshipInfo{
			AuthorName:        "Justin Grant",
			AuthorEmail:       "justin@legendrail.com",
			AuthoredTimestamp: time.Date(2026, 10, 14, 21, 30, 0, 0, time.UTC),
		},
		Notarization: NotarizationInfo{
			TSAAuthority: "DigiCert",
			TSATimestamp: time.Date(2026, 10, 14, 21, 30, 5, 0, time.UTC),
		},
	}

	if err := SignAttestation(record, priv); err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	if record.Signature.SignatureBase64 == "" {
		t.Errorf("expected signature to be populated")
	}
	if record.Authorship.SigningKeyID == "" {
		t.Errorf("expected signing key ID to be populated")
	}

	valid, err := VerifyAttestation(record, pub)
	if err != nil || !valid {
		t.Fatalf("verification failed: %v", err)
	}

	// Format JSON
	indented, err := record.MarshalIndent()
	if err != nil || len(indented) == 0 {
		t.Errorf("failed MarshalIndent: %v", err)
	}
}

func TestVerifyAttestation_TamperDetection(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed keygen: %v", err)
	}

	record := &AttestationRecord{
		Version: "1.0",
		Repository: RepositoryInfo{
			CommitHash: "original_commit_hash",
		},
		Authorship: AuthorshipInfo{
			AuthorName: "Justin Grant",
		},
	}

	if err := SignAttestation(record, priv); err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Tamper with commit hash
	record.Repository.CommitHash = "tampered_commit_hash"

	valid, err := VerifyAttestation(record, pub)
	if valid || !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature on tampered record, got %v", err)
	}
}

func TestVerifyAttestation_InvalidKeysAndAlgorithms(t *testing.T) {
	_, priv, _ := GenerateKeyPair()
	record := &AttestationRecord{
		Version: "1.0",
		Signature: SignatureInfo{
			Algorithm:       "rsa",
			SignatureBase64: "dGVzdA==",
		},
	}

	// Test invalid pub key size
	if _, err := VerifyAttestation(record, []byte{1, 2, 3}); !errors.Is(err, ErrMissingKey) {
		t.Errorf("expected ErrMissingKey for short public key, got %v", err)
	}

	pub := priv.Public().(ed25519.PublicKey)
	// Test unsupported algorithm
	if _, err := VerifyAttestation(record, pub); err == nil {
		t.Errorf("expected error for unsupported algorithm")
	}

	// Test invalid base64 signature
	record.Signature.Algorithm = "ed25519"
	record.Signature.SignatureBase64 = "not-valid-base64%%%"
	if _, err := VerifyAttestation(record, pub); err == nil {
		t.Errorf("expected error for invalid base64 signature")
	}

	// Test sign with invalid private key
	if err := SignAttestation(record, []byte{1, 2, 3}); !errors.Is(err, ErrMissingKey) {
		t.Errorf("expected ErrMissingKey for short private key, got %v", err)
	}
}

func TestCanonicalize_Errors(t *testing.T) {
	// Function cannot be marshaled to JSON
	ch := make(chan int)
	_, err := Canonicalize(ch)
	if err == nil {
		t.Errorf("expected error for unmarshalable channel")
	}

	// Direct unsupported type in encodeCanonical
	var buf bytes.Buffer
	err = encodeCanonical(&buf, complex(1, 2))
	if err == nil {
		t.Errorf("expected error for complex number")
	}
}

func TestCanonicalize_MoreTypes(t *testing.T) {
	input := map[string]any{
		"f": false,
		"empty_arr": []any{},
		"empty_map": map[string]any{},
	}
	canonical, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := `{"empty_arr":[],"empty_map":{},"f":false}`
	if string(canonical) != expected {
		t.Errorf("expected %s, got %s", expected, string(canonical))
	}
}

func TestCanonicalize_NestedErrors(t *testing.T) {
	var buf bytes.Buffer
	arrErr := encodeCanonical(&buf, []any{complex(1, 1)})
	if arrErr == nil {
		t.Errorf("expected error for bad element in array")
	}

	mapErr := encodeCanonical(&buf, map[string]any{"bad": complex(1, 1)})
	if mapErr == nil {
		t.Errorf("expected error for bad value in map")
	}
}
