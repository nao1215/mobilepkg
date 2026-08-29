# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic Versioning.

## [Unreleased]

### Added

- Scoop bucket for Windows: tagged releases now publish `bucket/mobilepkg.json`, so `scoop bucket add nao1215-mobilepkg https://github.com/nao1215/mobilepkg` installs the CLI.
- The end-to-end suite runs on Windows and macOS as well as Linux.

### Changed

- Dependencies updated (`github.com/nao1215/markdown` 0.13.0 to 1.0.0, `google.golang.org/protobuf`, `golang.org/x/image`, `golang.org/x/sys`, `github.com/stretchr/testify`), and every third-party GitHub Action is now pinned by commit SHA.
- The end-to-end bootstrap is `go run ./e2e/runner` instead of `e2e/run.sh`, and no spec shells out or reads a host environment variable, so the suite does not depend on Git for Windows.
- The end-to-end suite runs against atago v0.21.0, and `make tools` installs the runner.
- CI builds artifacts, E2E and coverage with the current stable Go toolchain; the unit-test matrix still pins the go.mod floor (1.25) alongside the newest release.

### Fixed

- The GoReleaser configuration is valid for GoReleaser v2 again. It declared no `version:` and used two properties removed in v2 (`snapshot.name_template`, `archives.format_overrides.format`), so the next tagged release would have failed.
- `CONTRIBUTING.md` said Go 1.24 was enough; `go.mod` has required 1.25 since 0.2.1.

## [0.4.0] - 2026-04-01

### Added

- WebView analysis reads `const-string/jumbo` operands and detects `setMixedContentMode` by argument value.

### Fixed

- Fewer cleartext-URL and secret false positives: Java class names and additional hosts are excluded, exclusion matches on exact host rather than URL prefix, and ad SDK and game engine prefixes are recognized as library code.
- Secret findings mask only the matched text instead of surrounding context.
- XAPK handling skips non-DEX splits (OBB, asset packs, config) when scanning, selects splits by DEX content rather than by name substring, counts only DEX-bearing splits against the `maxInnerAPKs` limit, and distinguishes oversize from corrupt inner APKs in its diagnostics.
- Only the worst `setMixedContentMode` finding per calling method is reported.

## [0.3.0] - 2026-03-31

### Added

- WebView argument tracking and wider WebView misconfiguration detection.
- Network Security Config parsing extended, plus iOS App Transport Security analysis.
- Manifest extraction covers `testOnly`, `profileableByShell`, the `<profileable>` element, provider permissions, and certificate details including DSA key size.
- Secret detection patterns unified across platforms with hash-based finding IDs.

### Changed

- Dangerous API findings originating in known library code are downgraded in severity.
- Shared secret patterns extracted into `internal/secrets`.
- README rewritten around what the tool actually reports, including a detection coverage table and a section on known limitations and common false positives.

### Fixed

- Inner APKs in XAPK and APKS bundles are validated before parsing, string pool and table entry allocations are capped to prevent an out-of-memory denial of service on crafted input, per-string allocation in the binary XML string pool is bounded, and a candidate that fails validation is skipped rather than aborting the search.
- Exported component fingerprints include browsable, authorities, `grantUriPermissions` and permission state, so a baseline diff no longer misses those changes.
- `cleartextTrafficPermitted` is inherited from a parent `domain-config`.
- iOS provisioning profile expiry reaches the findings.
- Deep links and network endpoints are normalized and deduplicated, and an unresolved resource in the display name falls back to the package name.

## [0.2.1] - 2026-03-30

### Changed

- `golang.org/x/image` updated, and Go 1.24 dropped from the test matrix to match the `go.mod` floor of 1.25.

## [0.2.0] - 2026-03-30

### Added

- DEX parsing and security scanning for APK, XAPK, APKS and AAB packages.

## [0.1.0] - 2026-03-29

Initial public release.

### Added

- Go library and CLI for inspecting APK, XAPK, APKS, AAB, and IPA packages.
- `mobilepkg inspect`, `mobilepkg compare`, and `mobilepkg version` commands.
- Unified inspection APIs: `InspectFile`, `Inspect`, `InspectWithBaseline`, and `Compare`.
- Structured JSON report output via `ReportFile`, plus Markdown summary and RDJSONL export helpers.
- CI-oriented fail conditions with severity thresholds and baseline comparison support.
- Android metadata extraction for identity, version, SDK constraints, permissions, exported components, entry points, icons, and network security configuration.
- Android signing inspection for JAR signing and APK signing block certificates, including debug and expired certificate findings.
- Android security findings for `debuggable`, `allowBackup`, `usesCleartextTraffic`, dangerous permissions, exported components, and deep links.
- iOS metadata extraction for bundle identity, versions, executable, minimum OS version, Info.plist permissions, entitlements, icons, and provisioning profile details.
- iOS security findings for entitlement-driven debug builds such as `get-task-allow`, plus endpoint extraction from URL schemes and associated domains.
- Archive safety validation and typed inspection errors for unsupported, corrupt, malformed, or oversized inputs.
- GitHub Actions workflows for multi-platform tests, coverage, linting, release builds, and reviewdog integration.
