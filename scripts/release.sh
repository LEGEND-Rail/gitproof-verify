#!/usr/bin/env bash
set -euo pipefail

# GitProof-Verify Deterministic Release Pipeline
# Usage: ./scripts/release.sh <tag> (e.g. ./scripts/release.sh v0.1.0)

TAG="${1:-}"
if [ -z "${TAG}" ]; then
  echo "❌ Error: Release tag required (e.g. ./scripts/release.sh v0.1.0)"
  exit 1
fi

if [[ "${TAG}" != v* ]]; then
  echo "❌ Error: Tag must start with 'v' (e.g. v0.1.0)"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${SCRIPT_DIR}"

echo "🚀 Starting release for ${TAG}..."
sed -i '' "s/Version   = \".*\"/Version   = \"${TAG}\"/" cmd/gproof-verify/main.go

# Cross-compile multi-arch release binaries
echo "⚙️ Cross-compiling multi-architecture binaries..."
DIST_DIR="dist/${TAG}"
rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

COMMIT_HASH="$(git rev-parse --short HEAD)"
LDFLAGS="-s -w -X main.Version=${TAG} -X main.GitCommit=${COMMIT_HASH}"

GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="${LDFLAGS}" -o "${DIST_DIR}/gproof-verify-darwin-arm64" ./cmd/gproof-verify
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="${LDFLAGS}" -o "${DIST_DIR}/gproof-verify-darwin-amd64" ./cmd/gproof-verify
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="${LDFLAGS}" -o "${DIST_DIR}/gproof-verify-linux-amd64" ./cmd/gproof-verify
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="${LDFLAGS}" -o "${DIST_DIR}/gproof-verify-linux-arm64" ./cmd/gproof-verify
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="${LDFLAGS}" -o "${DIST_DIR}/gproof-verify-windows-amd64.exe" ./cmd/gproof-verify

# Package compressed archives
echo "📦 Packaging archives (.tar.gz and .zip)..."
tar -czf "${DIST_DIR}/gproof-verify-darwin-arm64.tar.gz" -C "${DIST_DIR}" gproof-verify-darwin-arm64
tar -czf "${DIST_DIR}/gproof-verify-darwin-amd64.tar.gz" -C "${DIST_DIR}" gproof-verify-darwin-amd64
tar -czf "${DIST_DIR}/gproof-verify-linux-amd64.tar.gz" -C "${DIST_DIR}" gproof-verify-linux-amd64
tar -czf "${DIST_DIR}/gproof-verify-linux-arm64.tar.gz" -C "${DIST_DIR}" gproof-verify-linux-arm64
(cd "${DIST_DIR}" && zip -q gproof-verify-windows-amd64.zip gproof-verify-windows-amd64.exe)

# Checksums
echo "🔐 Generating checksums..."
(cd "${DIST_DIR}" && sha256sum gproof-verify-* > SHA256SUMS.txt)
cat "${DIST_DIR}/SHA256SUMS.txt"

# Git commit, tag, and push
echo "🏷️ Tagging and pushing to git..."
git add cmd/gproof-verify/main.go
git commit -m "release(${TAG}): update Version to ${TAG}" || true
git tag -a "${TAG}" -m "release: ${TAG}" || true
git push origin main --tags

echo "🎉 Release ${TAG} tag pushed! GitHub Actions runner on forras will publish the release."
