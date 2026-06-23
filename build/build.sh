#!/usr/bin/env bash
#
# Build the installable Joomla package for Security Guard.
#
# Produces a single archive in the repository root:
#   pkg_securityguard-<version>.zip   – installs the component and the system
#                                       plugin together in one step.
#
# Usage: bash build/build.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/src"
WORK="$ROOT/build/.work"

# --- read version from the package manifest -------------------------------
PKG_MANIFEST="$SRC/pkg_securityguard.xml"
VERSION="$(sed -n 's/.*<version>\([^<]*\)<\/version>.*/\1/p' "$PKG_MANIFEST" | head -n1)"
if [ -z "$VERSION" ]; then
    echo "ERROR: could not read <version> from $PKG_MANIFEST" >&2
    exit 1
fi
echo "Building Security Guard v$VERSION"

OUTPUT="$ROOT/pkg_securityguard-$VERSION.zip"

# --- portable "zip the contents of a dir at archive root" -----------------
# Uses the `zip` tool when available, otherwise falls back to Python's
# zipfile module (so the build also runs on a bare Windows/dev machine).
PYTHON="$(command -v python3 || command -v python || true)"
zip_dir() {
    local out="$1" dir="$2"
    if command -v zip >/dev/null 2>&1; then
        ( cd "$dir" && zip -q -r -X "$out" . )
    elif [ -n "$PYTHON" ]; then
        "$PYTHON" - "$out" "$dir" <<'PY'
import os, sys, zipfile
out, src = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for root, _, files in os.walk(src):
        for name in sorted(files):
            full = os.path.join(root, name)
            rel = os.path.relpath(full, src).replace(os.sep, "/")
            z.write(full, rel)
PY
    else
        echo "ERROR: neither 'zip' nor Python is available" >&2
        exit 1
    fi
}

# --- clean ----------------------------------------------------------------
rm -f "$OUTPUT"
rm -rf "$WORK"
mkdir -p "$WORK/packages"

# --- inner component & plugin zips (bundled inside the package) ------------
zip_dir "$WORK/packages/com_securityguard.zip" "$SRC/com_securityguard"
zip_dir "$WORK/packages/plg_system_securityguard.zip" "$SRC/plg_system_securityguard"

# --- assemble the package layout ------------------------------------------
cp "$PKG_MANIFEST" "$WORK/pkg_securityguard.xml"
if [ -d "$SRC/language" ]; then
    cp -r "$SRC/language" "$WORK/language"
fi

# --- single installable package zip ---------------------------------------
zip_dir "$OUTPUT" "$WORK"

rm -rf "$WORK"

echo "Done: $(basename "$OUTPUT")"
