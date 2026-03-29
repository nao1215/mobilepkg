# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic Versioning.

## [Unreleased]

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
