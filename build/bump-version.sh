#!/usr/bin/env bash
#
# Stamp a version into every Joomla manifest.
# Called by semantic-release (prepareCmd) with the computed next version.
#
# Usage: bash build/bump-version.sh <version>
#
set -euo pipefail

VERSION="${1:?usage: build/bump-version.sh <version>}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

MANIFESTS=(
    "$ROOT/src/pkg_securityguard.xml"
    "$ROOT/src/com_securityguard/securityguard.xml"
    "$ROOT/src/plg_system_securityguard/securityguard.xml"
)

for f in "${MANIFESTS[@]}"; do
    sed -i.bak "s|<version>[^<]*</version>|<version>${VERSION}</version>|" "$f"
    rm -f "$f.bak"
    echo "  ${f#$ROOT/} -> $VERSION"
done

echo "Bumped all manifests to v$VERSION"
