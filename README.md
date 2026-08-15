# mobilepkg

[![MultiPlatformUnitTest](https://github.com/nao1215/mobilepkg/actions/workflows/test.yml/badge.svg)](https://github.com/nao1215/mobilepkg/actions/workflows/test.yml)
[![tested with atago](https://img.shields.io/badge/tested%20with-atago-7c3aed?logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI%2BPHBhdGggZmlsbD0iI2ZmZiIgZD0iTTMuNiA0LjIgMTEuOSAxMmwtOC4zIDcuOC0xLjktMi4yTDcuOSAxMiAxLjcgNi40eiIvPjxyZWN0IGZpbGw9IiNmZmYiIHg9IjEyLjYiIHk9IjE3LjIiIHdpZHRoPSI5LjciIGhlaWdodD0iMi44IiByeD0iMS40Ii8%2BPC9zdmc%2B&logoColor=white)](https://github.com/nao1215/atago)
[![Coverage](doc/coverage.svg)](https://github.com/nao1215/mobilepkg/actions/workflows/coverage.yml)
[![Build](https://github.com/nao1215/mobilepkg/actions/workflows/build.yml/badge.svg)](https://github.com/nao1215/mobilepkg/actions/workflows/build.yml)
[![reviewdog](https://github.com/nao1215/mobilepkg/actions/workflows/reviewdog.yml/badge.svg)](https://github.com/nao1215/mobilepkg/actions/workflows/reviewdog.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/nao1215/mobilepkg.svg)](https://pkg.go.dev/github.com/nao1215/mobilepkg)

![logo](./doc/image/mobilepkg_small_logo.png)

mobilepkg inspects APK, AAB, APKS, XAPK, and IPA files and emits package metadata plus security findings as JSON, Markdown, or RDJSONL. It is intended for release triage and CI checks.

It reads the package as a zip archive, parses the manifest and DEX bytecode in-process, and finishes in seconds. No Android SDK, Xcode, or device required. Runs on Linux, Windows, and macOS (Go 1.25+).

## Scope

- Manifest metadata, signing info, permissions, exported components, deep links, and network endpoints from Android packages (APK, XAPK, APKS, AAB).
- DEX bytecode scanning across base and split APKs for hardcoded secrets, cleartext HTTP URLs, dangerous API calls, and insecure WebView configuration.
- XAPK and APKS bundles read directly — no prior extraction needed.
- Markdown reports for `$GITHUB_STEP_SUMMARY` and pull request comments.
- Baseline diff for tracking permission, component, and version changes between releases.
- CI integration: `--fail-on warn` exits non-zero when findings exceed a severity threshold.

### Known limitations and common false positives

- On well-maintained production apps, mobilepkg typically reports `allow_backup`, a few exported components, and some dangerous API calls from third-party libraries. Library-originated API calls (e.g. crash reporters using `Runtime.exec`) are automatically downgraded to `warn/medium`.
- Cleartext URL findings from DEX strings may include legitimate logging or configuration endpoints that happen to use HTTP.
- iOS IPA inspection covers entitlements, ATS settings, code signing certificates, provisioning profile expiry, URL schemes, and associated domains. It does not scan compiled Swift/ObjC binaries for API calls or secrets. Android inspection is deeper.
- WebView argument tracking is lightweight: it checks the immediately preceding `const/4` or `const/16` instruction. Non-trivial argument flow (e.g. values loaded from fields or computed) falls back to conservative reporting.

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

```markdown
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

```markdown
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

### Detection coverage

| Category | Findings |
|----------|----------|
| Manifest | `debuggable`, `allowBackup`, `usesCleartextTraffic`, `testOnly`, `profileableByShell` |
| Network security config | Base-config cleartext, per-domain cleartext, nested domain-config inheritance, debug-overrides |
| Signing | Debug certificates, expired certificates, v1-only signing, weak digest (MD5/SHA-1), weak key size (RSA<2048, ECDSA<256), self-signed test certificates |
| Provisioning (iOS) | Expired provisioning profile |
| Components | Exported activities/services/receivers/providers with intent-filters and deep links. No-permission components elevated to warn/error. Browsable activities flagged. Provider authorities, readPermission, writePermission, grantUriPermissions extracted. |
| Permissions | Dangerous permissions (CAMERA, SMS, LOCATION, etc.) |
| iOS ATS | `NSAllowsArbitraryLoads`, insecure exception domains (`NSExceptionAllowsInsecureHTTPLoads`) |
| iOS entitlements | `get-task-allow` (debug build), URL schemes, associated domains |
| Secrets | Regex-based scan of manifest/plist metadata and DEX string tables (AWS keys, GCP API keys, GitHub tokens, private keys, bearer tokens, Firebase URLs, generic api_key/secret/credential patterns). Both sources use the same pattern list. |
| DEX WebView | `setJavaScriptEnabled(true)`, `addJavascriptInterface`, `setAllowFileAccess(true)`, `setAllowUniversalAccessFromFileURLs(true)`, `setWebContentsDebuggingEnabled(true)`, `setMixedContentMode`, `SslErrorHandler.proceed` bypass, `WebView.loadUrl("http://...")`. Boolean argument tracking via preceding `const/4`/`const/16`. Library-originated calls reported at reduced severity. |
| DEX APIs | `Runtime.exec`, `ProcessBuilder`, `DexClassLoader`, `PathClassLoader`, `Method.invoke`, `SmsManager.sendTextMessage`, `DevicePolicyManager.resetPassword`, `Cipher.getInstance`. Library-originated calls reported at reduced severity. |
| DEX cleartext | `http://` URLs in string tables (localhost/schema/spec URLs excluded). |

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
