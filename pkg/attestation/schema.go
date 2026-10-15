package attestation

import (
	"encoding/json"
	"time"
)

// RepositoryInfo defines repository snapshot identifiers.
type RepositoryInfo struct {
	OriginURL         string `json:"origin_url"`
	Branch            string `json:"branch"`
	CommitHash        string `json:"commit_hash"`
	TreeHash          string `json:"tree_hash"`
	TreeMerkleRoot    string `json:"tree_merkle_root"`
	OverallMerkleRoot string `json:"overall_merkle_root"`
}

// AuthorshipInfo defines author identity and timestamps.
type AuthorshipInfo struct {
	AuthorName         string    `json:"author_name"`
	AuthorEmail        string    `json:"author_email"`
	AuthoredTimestamp  time.Time `json:"authored_timestamp"`
	CommitterName      string    `json:"committer_name,omitempty"`
	CommitterEmail     string    `json:"committer_email,omitempty"`
	CommittedTimestamp time.Time `json:"committed_timestamp,omitempty"`
	SigningKeyID       string    `json:"signing_key_id"`
}

// NotarizationInfo captures RFC 3161 TSA and on-chain ledger anchors.
type NotarizationInfo struct {
	TSAAuthority        string    `json:"tsa_authority,omitempty"`
	TSATimestamp        time.Time `json:"tsa_timestamp,omitempty"`
	RFC3161TokenBase64  string    `json:"rfc3161_token_base64,omitempty"`
	OnChainBatchID      uint64    `json:"on_chain_batch_id,omitempty"`
	OnChainRoot         string    `json:"on_chain_root,omitempty"`
	OnChainContractAddr string    `json:"on_chain_contract_addr,omitempty"`
}

// SignatureInfo contains the cryptographic author seal.
type SignatureInfo struct {
	Algorithm       string `json:"algorithm"`
	SignatureBase64 string `json:"signature_base64"`
}

// AttestationRecord is the top-level immutable proof envelope.
type AttestationRecord struct {
	Version      string           `json:"version"`
	Repository   RepositoryInfo   `json:"repository"`
	Authorship   AuthorshipInfo   `json:"authorship"`
	Notarization NotarizationInfo `json:"notarization"`
	Signature    SignatureInfo    `json:"signature"`
}

// UnsignedRecord returns the payload structure used for cryptographic hashing and signing.
type UnsignedRecord struct {
	Version      string           `json:"version"`
	Repository   RepositoryInfo   `json:"repository"`
	Authorship   AuthorshipInfo   `json:"authorship"`
	Notarization NotarizationInfo `json:"notarization"`
}

// ToUnsigned converts an AttestationRecord into its pre-signature payload.
func (a *AttestationRecord) ToUnsigned() UnsignedRecord {
	return UnsignedRecord{
		Version:      a.Version,
		Repository:   a.Repository,
		Authorship:   a.Authorship,
		Notarization: a.Notarization,
	}
}

// MarshalIndent formats the attestation record into clean human-readable JSON.
func (a *AttestationRecord) MarshalIndent() ([]byte, error) {
	return json.MarshalIndent(a, "", "  ")
}
