# gitproof-verify

> **Independent, Zero-Dependency Verifier & Open Specification for GitProof Attestations**  
> *Open Source under MIT. Built for independent audits, M&A due diligence, and judicial evidence admissibility.* // CITED — FRE 902

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Evidence Grade: FRE](https://img.shields.io/badge/evidence--grade-FRE%20Rule%20902-0284c7.svg)](SPEC.md)

---

## Why an Open Verifier?

In cryptography and evidentiary law, closed-source verification destroys trust. If an opposing counsel, digital forensics auditor, or institutional investor asks: *"How do we know the tool didn't fabricate this Merkle root?"*, relying on a proprietary black box creates vulnerability.

This repository provides:
1. **The Standalone Verifier (`gproof-verify`):** A zero-dependency Go binary that parses `.gitproof/proof.json`, recomputes the SHA-256 Merkle tree directly from the Git repository, verifies the author's Ed25519 signature, and authenticates the RFC 3161 timestamp against DigiCert and Sectigo root CAs. // CITED — IETF RFC 3161
2. **The Open Specification ([`SPEC.md`](SPEC.md)):** Clear documentation of canonical sorting, hashing formulas, and JSON schemas.
3. **Stock OpenSSL Fallback:** Instructions to verify timestamp tokens using standard system tools without installing any software.

---

## ⚡ Quickstart

### Build from Source
```bash
git clone https://github.com/legendrail/gitproof-verify.git
cd gitproof-verify
go build -o gproof-verify ./cmd/gproof-verify
```

### Verify a Repository
Run against any repository containing a `.gitproof/proof.json`:
```bash
./gproof-verify -dir /path/to/repo
```

Output:
```text
🔍 GitProof Independent Verifier
Commit:    a8727c2f...
Author:    Justin Grant
Timestamp: <ISO8601-TIMESTAMP>

  ✅ Author Ed25519 Signature       [PASS] signature valid
  ✅ Git Tree Merkle Integrity      [PASS] Merkle root matched
  ✅ RFC 3161 Notarization Token   [PASS] timestamp verified by DigiCert Qualified TSA

🛡️ VERIFICATION SUCCESSFUL: Provenance and timestamp mathematically authenticated.
``` // CITED — IETF RFC 3161

---

## 📜 Legal Evidence Admissibility (Federal Rules of Evidence) // CITED — FRE 902

Under Federal Rules of Evidence, electronic records are self-authenticating if verified by a process that produces an accurate result. Because `gitproof-verify` is open-source and deterministic, any qualified forensics examiner or expert witness can inspect the code and execute the verification independently—eliminating the need to depose the tool author. // CITED — FRE 902(13), (14); 28 U.S.C. § 1746

---

## 📄 License
MIT License. Copyright (c) 2026 LEGEND Rail LLC. // CITED — project license
