#!/usr/bin/env bash
#
# run.sh builds mobilepkg from this checkout and runs the atago end-to-end
# suite (e2e/atago/*.atago.yaml) against the real binary. mobilepkg is fully
# hermetic: it inspects a package file in-process (no Android SDK / Xcode /
# device / network). The only committed fixture is the small intentionally-
# vulnerable AndroGoat APK; the specs reach it via $MOBILEPKG_TESTDATA so the
# documented CLI behaviour cannot silently rot.
#
# The test DEFINITIONS are atago YAML — this script is only the environment
# bootstrap (a plain shell program, not a test framework).
#
# Environment contract used by the specs:
#   PATH               mobilepkg resolves here (built from this checkout)
#   MOBILEPKG_TESTDATA absolute path to this repo's testdata/ fixtures
#                        (testdata/android/androgoat_rich.apk is committed)
#
# Usage: e2e/run.sh [atago args...]        (e.g. e2e/run.sh --filter inspect)
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

if ! command -v atago >/dev/null 2>&1; then
	echo "e2e: atago is not installed. Install it from https://github.com/nao1215/atago" >&2
	echo "e2e: e.g. 'go install github.com/nao1215/atago@latest' (CI uses nao1215/setup-atago)" >&2
	exit 127
fi
if [ ! -f "$REPO_ROOT/testdata/android/androgoat_rich.apk" ]; then
	echo "e2e: committed fixture testdata/android/androgoat_rich.apk missing" >&2
	exit 127
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/mobilepkg-e2e.XXXXXX")"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT
mkdir -p "$TMP/bin"

echo "e2e: building mobilepkg..."
(cd "$REPO_ROOT" && env CGO_ENABLED=0 go build -o "$TMP/bin/mobilepkg" ./cmd/mobilepkg)

# Put the e2e-built mobilepkg first on PATH so the specs exercise that binary.
export PATH="$TMP/bin:$PATH"
export MOBILEPKG_TESTDATA="$REPO_ROOT/testdata"

echo "e2e: mobilepkg $("$TMP/bin/mobilepkg" version | head -1)"
# Extra args (e.g. --filter X) go before the path so the flag parser sees them.
atago run "$@" "$SCRIPT_DIR/atago"
