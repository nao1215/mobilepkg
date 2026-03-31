# mobilepkg

[![MultiPlatformUnitTest](https://github.com/nao1215/mobilepkg/actions/workflows/test.yml/badge.svg)](https://github.com/nao1215/mobilepkg/actions/workflows/test.yml)
[![Coverage](https://github.com/nao1215/mobilepkg/actions/workflows/coverage.yml/badge.svg)](https://github.com/nao1215/mobilepkg/actions/workflows/coverage.yml)
[![Build](https://github.com/nao1215/mobilepkg/actions/workflows/build.yml/badge.svg)](https://github.com/nao1215/mobilepkg/actions/workflows/build.yml)
[![reviewdog](https://github.com/nao1215/mobilepkg/actions/workflows/reviewdog.yml/badge.svg)](https://github.com/nao1215/mobilepkg/actions/workflows/reviewdog.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/nao1215/mobilepkg.svg)](https://pkg.go.dev/github.com/nao1215/mobilepkg)

![logo](./doc/image/mobilepkg_small_logo.png)

A Go library and CLI for fast mobile package triage. One call extracts metadata, permissions, exported components, signing info, and security findings from APK, XAPK, APKS, AAB, and IPA files.

mobilepkg is built for security engineers who need a quick initial assessment of a mobile package — identifying debug builds, hardcoded secrets, dangerous API usage, exported components, and deep links — without a full reverse-engineering workflow. It reads the package as a zip archive, parses the manifest and DEX bytecode in-process, and finishes in seconds. No Android SDK, Xcode, or device required.

mobilepkg runs on Linux, Windows, and macOS, and supports Go 1.25 or later.

### What it does well

- Extracts manifest metadata, signing info, permissions, exported components, deep links, and network endpoints from Android packages (APK, XAPK, APKS, AAB).
- Scans all DEX files across base and split APKs for hardcoded secrets (AWS keys, GCP API keys, GitHub tokens), cleartext HTTP URLs, dangerous API calls (Runtime.exec, DexClassLoader), and insecure WebView configuration.
- Reads XAPK and APKS bundles directly — no need to extract them first.
- Outputs Markdown reports suitable for `$GITHUB_STEP_SUMMARY` and pull request comments.
- Supports baseline diff to track permission, component, and version changes between releases.
- CI integration: `--fail-on warn` exits non-zero when findings exceed a severity threshold.

### What to expect with normal apps

On well-maintained production apps, mobilepkg typically reports `allow_backup`, a few exported components, and some dangerous API calls from third-party libraries. Library-originated API calls (e.g. crash reporters using `Runtime.exec`) are automatically downgraded to `warn/medium` to distinguish them from app-level code. Cleartext URL findings from DEX strings may include legitimate logging or configuration endpoints that happen to use HTTP.

### iOS coverage

iOS IPA inspection currently covers entitlements (including `get-task-allow` debug detection), code signing certificate validation, URL schemes, and associated domains. It does not scan compiled Swift/ObjC binaries for API calls or secrets. Android inspection is deeper.

| Format | Platform | Description |
|--------|----------|-------------|
| APK | Android | Standard Android package |
| XAPK | Android | APKPure extended package |
| APKS | Android | Bundletool APK set |
| AAB | Android | Android App Bundle |
| IPA | iOS | Standard iOS package |

## Install

```bash
go install github.com/nao1215/mobilepkg/cmd/mobilepkg@latest  # CLI
go get github.com/nao1215/mobilepkg                            # library
```

## CLI

### inspect — Inspect a mobile package

The primary command. Extracts package facts and runs analysis in one step.

```bash
$ mobilepkg inspect app.apk                                # JSON output (default)
$ mobilepkg inspect --format markdown app.apk              # Markdown summary
$ mobilepkg inspect --format markdown app.xapk             # XAPK works the same way
$ mobilepkg inspect --fail-on warn app.apk                 # CI: exit 1 if severity >= warn
$ mobilepkg inspect --baseline prev.json app.apk           # diff against previous result
```

#### Markdown output

The `--format markdown` output leads with the most actionable information — top findings and severity counts — before expanding into component and endpoint details. It is designed for `$GITHUB_STEP_SUMMARY`, pull request comments, and manual review.

<details>
<summary>Example: vulnerable app (AndroGoat)</summary>

On an intentionally vulnerable app like [AndroGoat](https://github.com/satishpatnayak/AndroGoat), the report surfaces debug builds, hardcoded AWS keys, command injection via `Runtime.exec`, and unguarded exported components:

```
## Top Findings
> [!WARNING]
> 10 finding(s) at warning severity or above.

| ID | Severity | Confidence | Message |
|----|----------|------------|---------|
| dex.api.java.lang.Runtime.exec... | error | high | Runtime.exec() called — potential command injection risk |
| dex.secret.aws_key... | error | high | potential aws_key found in DEX string table |
| manifest.debuggable | error | high | application is debuggable |
| signing.debug_cert | error | high | signed with debug certificate |
| dex.cleartext... | warn | medium | cleartext HTTP URL found in DEX strings: demo.testfire.net |
| manifest.allow_backup | warn | high | application allows backup |
| exported.provider... | warn | high | exported provider: ...ContentProviderActivity |
```

</details>

<details>
<summary>Example: normal app (F-Droid)</summary>

On a well-maintained production app like F-Droid, findings are less severe. Library-originated API calls are flagged at reduced severity. The deep link and endpoint sections show the app's registered URI handlers:

```
## Top Findings
> [!WARNING]
> 6 finding(s) at warning severity or above.

| ID | Severity | Confidence | Message |
|----|----------|------------|---------|
| dex.api...Runtime.exec...compat.FileCompat | error | high | Runtime.exec() called (in app code) |
| dex.api...Runtime.exec...acra... | warn | medium | Runtime.exec() called (in library) |
| dex.cleartext.logback.qos.ch | warn | medium | cleartext HTTP URL found in DEX strings |
| manifest.allow_backup | warn | high | application allows backup |

## Network Endpoints
| Endpoint | Source | Confidence |
|----------|--------|------------|
| f-droid.org | intent_filter | high |
| play.google.com | intent_filter | high |
| market://details | intent_filter | high |
```

</details>

#### JSON output

The default JSON output is a `ReportFile` with `schema_version`, `tool_version`, and `result`:

<details>
<summary>Example JSON (AndroGoat)</summary>

```json
{
  "schema_version": "1.0.0",
  "tool_version": "0.1.0",
  "result": {
    "platform": "android",
    "format": "apk",
    "identity": {
      "identifier": "owasp.sat.agoat",
      "display_name": "AndroGoat - Insecure App (Kotlin)"
    },
    "version": { "marketing": "1.0", "build": "1" },
    "debuggable": true,
    "allow_backup": true,
    "permissions": [
      { "canonical": "camera",  "raw_name": "android.permission.CAMERA",  "source": "manifest" },
      { "canonical": "network", "raw_name": "android.permission.INTERNET", "source": "manifest" }
    ],
    "exported_components": [
      { "kind": "provider", "name": "owasp.sat.agoat.ContentProviderActivity", "exported": true },
      { "kind": "receiver", "name": "owasp.sat.agoat.ShowDataReceiver",       "exported": true }
    ],
    "signing": {
      "scheme": "v1+v2",
      "certificates": [{ "subject": "Android Debug", "issuer": "Android Debug" }]
    },
    "findings": [
      { "severity": "error", "id": "manifest.debuggable",  "message": "application is debuggable" },
      { "severity": "error", "id": "signing.debug_cert",    "message": "signed with debug certificate" },
      { "severity": "warn",  "id": "manifest.allow_backup", "message": "application allows backup" }
    ],
    "secret_candidates": [],
    "diagnostics": []
  }
}
```

</details>

#### Baseline diff and CI

Save a report and use it as the baseline for the next run. The `--baseline` flag accepts a `report.json` file produced by a previous `inspect` run:

```bash
# Save today's result
mobilepkg inspect app.apk > baseline.json

# Compare against baseline in CI
mobilepkg inspect --baseline baseline.json --fail-on warn app.apk
```

When `--fail-on` is specified, the output includes a `verdict` field with `passed`, `reasons`, and `triggering_findings`, and the command exits with code 1 if the policy is violated.

### compare — Compare two packages

```bash
$ mobilepkg compare old.apk new.apk
```

Shows identity, version, and entry point changes, plus added/removed permissions, exported components, and network endpoints.

## Library

### InspectFile — One call, full result

```go
result, err := mobilepkg.InspectFile(ctx, "app.apk")
if err != nil {
    log.Fatal(err)
}

fmt.Println(result.Identity.Identifier)  // "com.example.app"
fmt.Println(result.Debuggable)           // true

for _, f := range result.Findings {
    fmt.Printf("[%s] %s\n", f.Severity, f.Message)
}
```

### What gets detected

| Category | Findings |
|----------|----------|
| Manifest | `debuggable`, `allowBackup`, `usesCleartextTraffic` |
| Signing | Debug certificates, expired certificates |
| Components | Exported activities/services/receivers/providers with intent-filters and deep links |
| Permissions | Dangerous permissions (CAMERA, SMS, LOCATION, etc.) |
| iOS | `get-task-allow` (debug build), URL schemes, associated domains |
| Endpoints | ATS exception domains, URL schemes, deep links from intent-filters |
| Secrets | Regex-based scan of manifest/plist metadata and DEX string tables (AWS keys, GCP API keys, GitHub tokens, private keys, bearer tokens, Firebase URLs) |
| DEX bytecode | Hardcoded secrets, insecure WebView APIs, cleartext HTTP URLs, dangerous API calls (Runtime.exec, DexClassLoader, reflection, SMS). Library-originated calls are reported at reduced severity. Scans all DEX files across base and split APKs (APK, XAPK, APKS) and all modules (AAB). |

### Fail conditions (CI)

```go
verdict := mobilepkg.Check(result, mobilepkg.DefaultFailPolicy())
if !verdict.Passed {
    os.Exit(1)
}
```

### Baseline diff

```go
result, _ := mobilepkg.InspectWithBaseline(ctx, "new.apk", prevResult)
fmt.Println(result.Diff.VersionChanged)
fmt.Println(result.Diff.AddedComponents)
```

### Output formats

```go
rf := mobilepkg.NewReportFile(result, "1.0.0")
mobilepkg.WriteReportJSON(os.Stdout, rf)       // JSON
mobilepkg.WriteSummaryMarkdown(os.Stdout, rf)   // Markdown
mobilepkg.WriteRDJSONL(os.Stdout, result.Findings, "app.apk") // reviewdog
```

## GitHub Actions

```yaml
- run: mobilepkg inspect --fail-on warn app.apk > report.json
- run: mobilepkg inspect --format markdown app.apk >> "$GITHUB_STEP_SUMMARY"
```

## Test Data

Examples use [AndroGoat](https://github.com/satishpatnayak/AndroGoat) ([v2.0.1](https://github.com/satishpatnayak/AndroGoat/releases/tag/v2.0.1)), an intentionally vulnerable Android app. The APK is under `testdata/no_commit/` for local testing only and is not committed.

```bash
mkdir -p testdata/no_commit
curl -L -o testdata/no_commit/AndroGoat.apk \
  https://github.com/satishpatnayak/AndroGoat/releases/download/v2.0.1/AndroGoat.apk
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Sponsorship

[Sponsor this project](https://github.com/sponsors/nao1215)

## Related or inspired Projects

- [shogo82148/androidbinary](https://github.com/shogo82148/androidbinary): Android binary file parser written in golang
- [nao1215/deapk(already public archived)](https://github.com/nao1215/deapk): parse android package (.apk), getting meta data and more.

## License

[MIT License](LICENSE)
