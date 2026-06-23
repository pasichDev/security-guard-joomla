#!/usr/bin/env bash
#
# Build installable Joomla packages for Security Guard.
#
# Produces, in dist/:
#   com_securityguard.zip               – the component
#   plg_system_securityguard.zip        – the system plugin
#   pkg_securityguard-<version>.zip      – the full package (component + plugin)
#
# Usage: bash build/build.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/src"
DIST="$ROOT/dist"
WORK="$ROOT/build/.work"

# --- read version from the package manifest -------------------------------
PKG_MANIFEST="$SRC/pkg_securityguard.xml"
VERSION="$(sed -n 's/.*<version>\([^<]*\)<\/version>.*/\1/p' "$PKG_MANIFEST" | head -n1)"
if [ -z "$VERSION" ]; then
    echo "ERROR: could not read <version> from $PKG_MANIFEST" >&2
    exit 1
fi
echo "Building Security Guard v$VERSION"

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
rm -rf "$DIST" "$WORK"
mkdir -p "$DIST" "$WORK/packages"

# --- component & plugin zips (contents at archive root) -------------------
zip_dir "$WORK/packages/com_securityguard.zip" "$SRC/com_securityguard"
zip_dir "$WORK/packages/plg_system_securityguard.zip" "$SRC/plg_system_securityguard"

# --- assemble the package layout ------------------------------------------
cp "$PKG_MANIFEST" "$WORK/pkg_securityguard.xml"
if [ -d "$SRC/language" ]; then
    cp -r "$SRC/language" "$WORK/language"
fi

# --- package zip ----------------------------------------------------------
zip_dir "$DIST/pkg_securityguard-$VERSION.zip" "$WORK"

# --- expose the inner zips as standalone artifacts too --------------------
cp "$WORK/packages/com_securityguard.zip" "$DIST/com_securityguard.zip"
cp "$WORK/packages/plg_system_securityguard.zip" "$DIST/plg_system_securityguard.zip"

rm -rf "$WORK"

echo "Done. Artifacts in dist/:"
ls -1 "$DIST"
