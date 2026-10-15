package attestation

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

var (
	ErrInvalidSignature = errors.New("signer: invalid signature")
	ErrMissingKey       = errors.New("signer: missing key")
)

// GenerateKeyPair generates a new cryptographic Ed25519 key pair for author sealing.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("signer: key generation failed: %w", err)
	}
	return pub, priv, nil
}

// PublicKeyFingerprint computes a SHA-256 fingerprint for public key identification.
func PublicKeyFingerprint(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])
}

// SignAttestation canonicalizes the unsigned record and attaches an Ed25519 author signature.
func SignAttestation(record *AttestationRecord, priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return ErrMissingKey
	}

	record.Authorship.SigningKeyID = PublicKeyFingerprint(priv.Public().(ed25519.PublicKey))

	unsigned := record.ToUnsigned()
	canonicalBytes, err := Canonicalize(unsigned)
	if err != nil {
		return fmt.Errorf("signer: canonicalization failed: %w", err)
	}

	sig := ed25519.Sign(priv, canonicalBytes)
	record.Signature = SignatureInfo{
		Algorithm:       "ed25519",
		SignatureBase64: base64.StdEncoding.EncodeToString(sig),
	}

	return nil
}

// VerifyAttestation verifies that the Ed25519 signature on record is valid against pubKey.
func VerifyAttestation(record *AttestationRecord, pubKey ed25519.PublicKey) (bool, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return false, ErrMissingKey
	}

	if record.Signature.Algorithm != "ed25519" {
		return false, fmt.Errorf("signer: unsupported signature algorithm %q", record.Signature.Algorithm)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(record.Signature.SignatureBase64)
	if err != nil {
		return false, fmt.Errorf("signer: invalid base64 signature: %w", err)
	}

	unsigned := record.ToUnsigned()
	canonicalBytes, err := Canonicalize(unsigned)
	if err != nil {
		return false, fmt.Errorf("signer: canonicalization failed: %w", err)
	}

	valid := ed25519.Verify(pubKey, canonicalBytes, sigBytes)
	if !valid {
		return false, ErrInvalidSignature
	}

	return true, nil
}
