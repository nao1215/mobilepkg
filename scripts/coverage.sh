#!/bin/sh
# Combine unit-test coverage with self-hosted E2E coverage into a single
# coverage.out. Unit tests report line coverage, but they never exercise the
# real mobilepkg binary the way an end user does; the self-hosted atago E2E
# specs do. Go 1.20+ lets us instrument a built binary (`go build -cover`) and
# collect its runtime coverage via GOCOVERDIR, so we can merge "what the tests
# cover" with "what a real run covers" and get one honest number.
#
# This is intentionally a separate, heavier target: `make test` / `make e2e`
# stay fast. Everything lands under .coverage/ (gitignored) except the final
# coverage.out / cover.html, which are the artifacts octocov and local tooling
# already consume, so no other config needs to change.
set -eu

cd "$(CDPATH= cd "$(dirname "$0")/.." && pwd)"
root="$(pwd)"
cov="${root}/.coverage"

rm -rf "${cov}"
mkdir -p "${cov}/unit" "${cov}/e2e" "${cov}/merged"

# 1. Unit-test coverage as raw covdata (GOCOVERDIR form) so it can be merged
#    with the E2E covdata below. -covermode=atomic must match the binary build.
echo ">> unit coverage -> ${cov}/unit"
go test -count=1 -cover -covermode=atomic -coverpkg=./... ./... \
	-args -test.gocoverdir="${cov}/unit"

# 2. Self-hosted E2E. e2e/run.sh builds a coverage-instrumented mobilepkg when
#    COVER is set and puts it first on PATH; atago passes GOCOVERDIR through to
#    the mobilepkg child processes (the specs do not use clear_env), so each run
#    writes its own covdata into ${cov}/e2e.
echo ">> e2e coverage -> ${cov}/e2e"
COVER=1 GOCOVERDIR="${cov}/e2e" "${root}/e2e/run.sh"

# 3. Merge the raw covdata and render the combined text profile + HTML report.
echo ">> merging unit + e2e covdata -> coverage.out"
go tool covdata merge -i="${cov}/unit,${cov}/e2e" -o="${cov}/merged"
go tool covdata textfmt -i="${cov}/merged" -o="${root}/coverage.out"

go tool cover -func=coverage.out | tail -n 1
go tool cover -html=coverage.out -o cover.html
echo ">> wrote coverage.out and cover.html (unit + e2e combined)"
