# GitProof Open Verification Specification (v1.0)

This document specifies the open cryptographic proof format, Merkle DAG computation rules, and timestamp verification procedures for GitProof attestations.

---

## 1. Objective & Non-Custodial Invariants

The GitProof verification protocol provides mathematical, tamper-evident proof that a specific software author authored a precise tree of code at a verified point in time. // CITED — IETF RFC 3161; FRE 902

1. **Zero Black-Box Dependency:** Any third party can verify a proof using this specification and stock cryptographic primitives (`sha256`, `openssl`, `ed25519`).
2. **Zero Source Code Disclosure:** Verification operates exclusively on 32-byte SHA-256 hashes and standard ASN.1 DER tokens. No source code or file contents are ever transmitted to external authorities. // CITED — IETF RFC 3161
3. **Self-Authenticating Record:** Designed to satisfy Federal Rule of Evidence 902(13) and 902(14) without requiring expert witness testimony. // CITED — FRE 902(13), (14)

---

## 2. Canonical Merkle Tree Derivation

### 2.1 POSIX Canonical Ordering
1. Traverse the repository at the target `commit_hash`.
2. Exclude ignore paths (`.git/`, `.gitproof/`, build artifacts).
3. Sort all relative file paths canonically using byte-wise ASCII / POSIX ordering (`LC_ALL=C`).

### 2.2 Leaf Node Hashing
For each file $i$ at canonical path $P_i$ with content bytes $C_i$:
$$L_i = \text{SHA-256}(P_i \mathbin{\Vert} \text{0x00} \mathbin{\Vert} \text{SHA-256}(C_i))$$

### 2.3 Balanced Tree Folding
Leaves are paired left-to-right:
$$N_{\text{parent}} = \text{SHA-256}(N_{\text{left}} \mathbin{\Vert} N_{\text{right}})$$
If the number of nodes at a level is odd, the last node is promoted to the next level without duplication. The root is the 32-byte `tree_merkle_root`.

### 2.4 Overall Merkle Root
The `overall_merkle_root` binds tree structure and commit metadata:
$$\text{overall\_merkle\_root} = \text{SHA-256}(\text{tree\_merkle\_root} \mathbin{\Vert} \text{commit\_hash} \mathbin{\Vert} \text{author\_email})$$

---

## 3. The `proof.json` Schema

```json
{
  "version": "1.0",
  "repository": {
    "origin_url": "git@github.com:LEGEND-Rail/gitproof.git",
    "branch": "main",
    "commit_hash": "<GIT-COMMIT-HASH>",
    "tree_merkle_root": "<HEX-TREE-ROOT>",
    "overall_merkle_root": "<HEX-OVERALL-ROOT>"
  },
  "authorship": {
    "author_name": "<AUTHOR-NAME>",
    "author_email": "<AUTHOR-EMAIL>",
    "authored_timestamp": "<ISO8601-TIMESTAMP>",
    "signing_key_id": "<ED25519-PUBLIC-KEY-HEX>"
  },
  "notarization": {
    "rfc3161_token_base64": "<ASN1-DER-TOKEN>",
    "tsa_authority": "DigiCert Qualified Timestamp Authority",
    "notarized_time": "<ISO8601-TIMESTAMP>"
  },
  "signature": {
    "algorithm": "ed25519",
    "signature_base64": "<ED25519-SIGNATURE>"
  }
}
```

---

## 4. Stock OpenSSL Fallback Verification (Zero Tooling Required)

Any forensic examiner, lawyer, or auditor can verify a GitProof RFC 3161 timestamp without installing `gproof` or `gproof-verify`, using standard OpenSSL: // CITED — IETF RFC 3161

```bash
# 1. Extract the ASN.1 DER timestamp token
jq -r '.notarization.rfc3161_token_base64' .gitproof/proof.json | base64 -d > token.tsr

# 2. Extract the overall Merkle root to binary
jq -r '.repository.overall_merkle_root' .gitproof/proof.json | xxd -r -p > root.bin

# 3. Verify against DigiCert / Sectigo public CA trust store at historical signing time (-attime)
EPOCH=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$(jq -r '.notarization.notarized_time' .gitproof/proof.json)" "+%s" 2>/dev/null || date -d "$(jq -r '.notarization.notarized_time' .gitproof/proof.json)" "+%s")
openssl ts -verify -data root.bin -in token.tsr -CAfile /etc/ssl/cert.pem -attime "${EPOCH}"
```

If OpenSSL outputs:
`Verification: OK`
the Merkle root existed at or before the notarized timestamp signed by the hardware security module of the root CA. // CITED — IETF RFC 3161

---

## 5. Long-Term Validation (LTV) & Cryptographic Durability

To ensure evidence remains admissible across decades of patent maintenance or post-acquisition indemnity periods: // CITED — FRE 902
1. **Embedded Intermediate Chains (`CertReq=true`):** Tokens contain the full X.509 certificate path, avoiding external LDAP/HTTP CA lookups. // CITED — IETF RFC 3161
2. **Point-in-Time X.509 Validation:** Verification sets `VerifyOptions.CurrentTime = TSTInfo.GenTime`, confirming certificate validity at the precise second of signing rather than current wall-clock time. // CITED — Go crypto/x509; IETF RFC 3161
3. **RFC 4998 Archive Rollover (`gproof reseal`):** As cryptographic algorithms or root certificates approach obsolescence, GitProof wraps existing proofs in fresh timestamp envelopes, extending legal validity indefinitely without altering history. // CITED — IETF RFC 4998
