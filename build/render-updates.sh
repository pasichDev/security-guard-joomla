#!/usr/bin/env bash
#
# Render the Joomla update-server XML from the template for a given version,
# pointing at the matching GitHub release asset. Output: public/updates.xml.
#
# Usage: bash build/render-updates.sh <version>
#
set -euo pipefail

VERSION="${1:?usage: build/render-updates.sh <version>}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="${GITHUB_REPOSITORY:-pasichDev/security-guard-joomla}"

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/v${VERSION}/pkg_securityguard-${VERSION}.zip"

mkdir -p "$ROOT/public"
sed -e "s|__VERSION__|${VERSION}|g" \
    -e "s|__DOWNLOAD_URL__|${DOWNLOAD_URL}|g" \
    "$ROOT/updates/updates.xml.tmpl" > "$ROOT/public/updates.xml"

echo "Rendered public/updates.xml for v$VERSION ($DOWNLOAD_URL)"
