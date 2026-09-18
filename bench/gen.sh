#!/bin/sh
# Writes the inputs of the himorime suite in bench/. Deterministic: the same
# arguments always write the same bytes, so a base and a head revision read
# the same input. Both revisions run the working tree's copy (${head_root}).
#
#   sh gen.sh apk N FILE [SHIFT]   an APK: the entries of the committed
#                                  testdata/android/androgoat_rich.apk plus a
#                                  classes.dex of N strings (see genapk/);
#                                  SHIFT changes the strings
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)

case "$1" in
apk)
	cd "$root"
	go run ./bench/genapk -from testdata/android/androgoat_rich.apk -strings "$2" -shift "${4:-0}" -out "$3"
	;;
*)
	echo "gen.sh: unknown kind $1" >&2
	exit 2
	;;
esac
