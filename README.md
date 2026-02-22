# mobilepkg

[![MultiPlatformUnitTest](https://github.com/nao1215/mobilepkg/actions/workflows/test.yml/badge.svg)](https://github.com/nao1215/mobilepkg/actions/workflows/test.yml)
[![Coverage](https://github.com/nao1215/mobilepkg/actions/workflows/coverage.yml/badge.svg)](https://github.com/nao1215/mobilepkg/actions/workflows/coverage.yml)
[![Build](https://github.com/nao1215/mobilepkg/actions/workflows/build.yml/badge.svg)](https://github.com/nao1215/mobilepkg/actions/workflows/build.yml)
[![reviewdog](https://github.com/nao1215/mobilepkg/actions/workflows/reviewdog.yml/badge.svg)](https://github.com/nao1215/mobilepkg/actions/workflows/reviewdog.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/nao1215/mobilepkg.svg)](https://pkg.go.dev/github.com/nao1215/mobilepkg)

![logo](./doc/image/mobilepkg_small_logo.png)

A Go library and CLI for fast mobile package triage. One call extracts metadata, permissions, exported components, signing info, and security findings from APK, XAPK, APKS, AAB, and IPA files. Designed for initial assessment — not a replacement for deep reverse-engineering tools.

mobilepkg runs on Linux, Windows, and macOS, and supports Go 1.24 or later.

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
$ mobilepkg inspect app.apk
```

The output is a JSON `ReportFile` with `schema_version`, `tool_version`, and `result`:

<details>
<summary>Example output (AndroGoat — <a href="https://github.com/satishpatnayak/AndroGoat/releases/tag/v2.0.1">satishpatnayak/AndroGoat v2.0.1</a>)</summary>

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

Options:

```bash
mobilepkg inspect --format markdown app.apk     # human-readable summary
mobilepkg inspect --baseline prev.json app.apk  # compare against previous result
mobilepkg inspect --fail-on warn app.apk        # CI: exit 1 if severity >= warn
```

When `--fail-on` is specified, the JSON output includes a `verdict` field with `passed`, `reasons`, and `triggering_findings`, and the command exits with code 1 if the policy is violated. The Markdown output also shows the verdict when present.

The `--baseline` flag accepts a `report.json` file produced by a previous `inspect` run. Since the output format is always the same `ReportFile`, you can save today's result and use it as tomorrow's baseline directly.

<details>
<summary>Markdown output example (<code>--format markdown --fail-on warn</code>)</summary>

The Markdown output is designed for `$GITHUB_STEP_SUMMARY` and manual review:

```markdown
# mobilepkg Inspection Report
## Package
| Field | Value |
|-------|-------|
| Platform | android |
| Format | apk |
| Identifier | owasp.sat.agoat |
| Display Name | AndroGoat |
| Version | 1.0 (build 1) |
| Min SDK | 19 |

## Top Findings
> [!WARNING]
> 4 finding(s) at warning severity or above.

| ID | Severity | Confidence | Message |
|----|----------|------------|---------|
| manifest.debuggable | error | high | application is debuggable |
| signing.debug_cert | error | high | signed with debug certificate |
| manifest.allow_backup | warn | high | application allows backup |
| exported.provider... | warn | high | exported provider (no permission) |

## Exported Components
| Kind | Name | Required Permission | Authorities |
|------|------|---------------------|-------------|
| provider | owasp.sat.agoat.ContentProviderActivity | | |
| receiver | owasp.sat.agoat.ShowDataReceiver | | |

## Verdict
> [!WARNING]
> FAILED
- finding "manifest.debuggable": severity=error confidence=high
- finding "signing.debug_cert": severity=error confidence=high
- finding "manifest.allow_backup": severity=warn confidence=high
```

</details>

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

What gets detected:

| Category | Findings |
|----------|----------|
| Manifest | `debuggable`, `allowBackup`, `usesCleartextTraffic` |
| Signing | Debug certificates, expired certificates |
| Components | Exported activities/services/receivers/providers with intent-filters and deep links |
| Permissions | Dangerous permissions (CAMERA, SMS, LOCATION, etc.) |
| iOS | `get-task-allow` (debug build) |
| Endpoints | ATS exception domains, URL schemes, associated domains |
| Secrets | Regex-based scan of manifest/plist/entitlement metadata (AWS keys, GitHub tokens, API keys, bearer tokens). Does not scan dex bytecode or resource files. |

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

## License

[MIT License](LICENSE)
