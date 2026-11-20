# mobilepkg

<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-1-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->
[![MultiPlatformUnitTest](https://github.com/nao1215/mobilepkg/actions/workflows/test.yml/badge.svg)](https://github.com/nao1215/mobilepkg/actions/workflows/test.yml)
[![Build](https://github.com/nao1215/mobilepkg/actions/workflows/build.yml/badge.svg)](https://github.com/nao1215/mobilepkg/actions/workflows/build.yml)
[![E2E](https://github.com/nao1215/mobilepkg/actions/workflows/e2e.yml/badge.svg)](https://github.com/nao1215/mobilepkg/actions/workflows/e2e.yml)
[![Coverage](doc/coverage.svg)](https://github.com/nao1215/mobilepkg/actions/workflows/coverage.yml)
[![Gitleaks](https://github.com/nao1215/mobilepkg/actions/workflows/gitleaks.yml/badge.svg)](https://github.com/nao1215/mobilepkg/actions/workflows/gitleaks.yml)
[![Trivy](https://github.com/nao1215/mobilepkg/actions/workflows/trivy.yml/badge.svg)](https://github.com/nao1215/mobilepkg/actions/workflows/trivy.yml)
[![govulncheck](https://github.com/nao1215/mobilepkg/actions/workflows/govulncheck.yml/badge.svg)](https://github.com/nao1215/mobilepkg/actions/workflows/govulncheck.yml)
[![Gosec](https://github.com/nao1215/mobilepkg/actions/workflows/gosec.yml/badge.svg)](https://github.com/nao1215/mobilepkg/actions/workflows/gosec.yml)
[![reviewdog](https://github.com/nao1215/mobilepkg/actions/workflows/reviewdog.yml/badge.svg)](https://github.com/nao1215/mobilepkg/actions/workflows/reviewdog.yml)
[![tested with atago](https://img.shields.io/badge/tested%20with-atago-7c3aed?logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI%2BPHBhdGggZmlsbD0iI2ZmZiIgZD0iTTMuNiA0LjIgMTEuOSAxMmwtOC4zIDcuOC0xLjktMi4yTDcuOSAxMiAxLjcgNi40eiIvPjxyZWN0IGZpbGw9IiNmZmYiIHg9IjEyLjYiIHk9IjE3LjIiIHdpZHRoPSI5LjciIGhlaWdodD0iMi44IiByeD0iMS40Ii8%2BPC9zdmc%2B&logoColor=white)](https://github.com/nao1215/atago)
[![measured with himorime](https://img.shields.io/badge/measured%20with-himorime-d9480f?logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI%2BPHBhdGggZmlsbD0ibm9uZSIgc3Ryb2tlPSIjZmZmIiBzdHJva2Utd2lkdGg9IjIuNCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBkPSJNNC4yIDE4LjVBOSA5IDAgMSAxIDE5LjggMTguNSIvPjxwYXRoIGZpbGw9Im5vbmUiIHN0cm9rZT0iI2ZmZiIgc3Ryb2tlLXdpZHRoPSIyLjQiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgZD0iTTEyIDE0LjUgMTYuNSA5Ii8%2BPGNpcmNsZSBmaWxsPSIjZmZmIiBjeD0iMTIiIGN5PSIxNC41IiByPSIyLjIiLz48L3N2Zz4=&logoColor=white)](https://github.com/nao1215/himorime)
[![Go Reference](https://pkg.go.dev/badge/github.com/nao1215/mobilepkg.svg)](https://pkg.go.dev/github.com/nao1215/mobilepkg)
[![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/nao1215/mobilepkg/total)](https://github.com/nao1215/mobilepkg/releases)
[![License](https://img.shields.io/github/license/nao1215/mobilepkg)](./LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/nao1215/mobilepkg/badge)](https://scorecard.dev/viewer/?uri=github.com/nao1215/mobilepkg)

![logo](./doc/image/mobilepkg_small_logo.png)

mobilepkg inspects APK, AAB, APKS, XAPK, and IPA files for release triage and CI checks, and writes package metadata and security findings as JSON, Markdown, or RDJSONL. It reads the package as a zip archive and parses the manifest and DEX bytecode in-process, so it needs no Android SDK, Xcode, or device. It runs on Linux, Windows, and macOS (Go 1.26.11+).

In a GitHub Actions workflow:

```yaml
- run: mobilepkg inspect --fail-on warn app.apk > report.json
- run: mobilepkg inspect --format markdown app.apk >> "$GITHUB_STEP_SUMMARY"
```

For Android packages it reports manifest metadata, signing, permissions, exported components, deep links and network endpoints, and scans the DEX bytecode of base and split APKs for hardcoded secrets, cleartext HTTP URLs, dangerous API calls and insecure WebView settings. XAPK and APKS bundles need no extraction first. A baseline diff tracks permission, component and version changes between releases, and `--fail-on warn` exits non-zero when findings reach a severity.

### Known limitations and common false positives

- Production apps usually get `allow_backup`, a few exported components, and some dangerous API calls from third-party libraries. Calls from libraries (for example crash reporters using `Runtime.exec`) are downgraded to `warn/medium`.
- Cleartext URLs found in DEX strings may be logging or configuration endpoints that use HTTP on purpose.
- For iOS IPA files, mobilepkg checks entitlements, ATS settings, code signing certificates, provisioning profile expiry, URL schemes and associated domains. It does not scan compiled Swift/ObjC binaries for API calls or secrets.
- WebView argument tracking only looks at the `const/4` or `const/16` instruction just before the call. Arguments loaded from fields or computed values are reported conservatively.

| Format | Platform | Description |
|--------|----------|-------------|
| APK | Android | Standard Android package |
| XAPK | Android | APKPure extended package |
| APKS | Android | Bundletool APK set |
| AAB | Android | Android App Bundle |
| IPA | iOS | Standard iOS package |

## Install

### Use "go install"

Requires Go 1.26.11 or later.

```bash
go install github.com/nao1215/mobilepkg/cmd/mobilepkg@latest  # CLI
go get github.com/nao1215/mobilepkg                           # library
```

### Download a release artifact

The [release page](https://github.com/nao1215/mobilepkg/releases) has `tar.gz` archives for Linux and macOS, `zip` archives for Windows, and `.deb`, `.rpm` and `.apk` packages for Linux, all for `amd64`, `arm64` and `386`. Put the `mobilepkg` binary from an archive on your `PATH`, or install a package:

```bash
sudo dpkg -i mobilepkg_0.6.0_linux_amd64.deb   # Debian, Ubuntu
sudo rpm -i mobilepkg_0.6.0_linux_amd64.rpm    # Fedora, RHEL
sudo apk add --allow-untrusted mobilepkg_0.6.0_linux_amd64.apk  # Alpine
```

## Verifying release integrity

Since v0.5.4, each release has `checksums.txt` signed with [cosign](https://github.com/sigstore/cosign) (keyless, as `checksums.txt.sigstore.json`), an SPDX SBOM per archive (`<archive>.sbom.json`), and SLSA build provenance attested via GitHub OIDC and attached as `multiple.intoto.jsonl`.

Verify the signed checksums, then your archive:

```shell
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp 'https://github.com/nao1215/mobilepkg/\.github/workflows/release\.yml@refs/tags/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt
sha256sum --check --ignore-missing checksums.txt
```

Verify the build provenance with the GitHub CLI:

```shell
gh attestation verify mobilepkg_<version>_<os>_<arch>.tar.gz --repo nao1215/mobilepkg
```

Or with [slsa-verifier](https://github.com/slsa-framework/slsa-verifier) and the `multiple.intoto.jsonl` asset:

```shell
slsa-verifier verify-artifact mobilepkg_<version>_<os>_<arch>.tar.gz \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/nao1215/mobilepkg \
  --source-tag v<version>
```

## CLI

### inspect

```bash
$ mobilepkg inspect app.apk                                # JSON output (default)
$ mobilepkg inspect --format markdown app.apk              # Markdown summary
$ mobilepkg inspect --format markdown app.xapk             # XAPK works the same way
$ mobilepkg inspect --fail-on warn app.apk                 # CI: exit 1 if severity >= warn
$ mobilepkg inspect --baseline prev.json app.apk           # diff against previous result
```

#### Markdown output

`--format markdown` puts the top findings and severity counts first, then the component and endpoint details. Use it for `$GITHUB_STEP_SUMMARY`, pull request comments, or reading by hand.

<details>
<summary>Example: vulnerable app (AndroGoat v2.0.1)</summary>

[AndroGoat](https://github.com/satishpatnayak/AndroGoat) is vulnerable on purpose. The first rows of its Top Findings section (17 rows in all):

```markdown
## Top Findings
> [!WARNING]  
> 17 finding(s) at warning severity or above.

| ID | Severity | Confidence | Message |
|---------|---------|---------|---------|
| dex.api.java.lang.Runtime.exec.Lowasp.sat.agoat.InputValidationsOSCMDInjectionMain2Activity. | error | high | Runtime.exec() called — potential command injection risk (in Lowasp/sat/agoat/InputValidationsOSCMDInjectionMain2Activity;) |
| dex.api.java.lang.Runtime.exec.Lowasp.sat.agoat.RootDetectionActivity. | error | high | Runtime.exec() called — potential command injection risk (in Lowasp/sat/agoat/RootDetectionActivity;) |
| dex.cleartext.demo.testfire.net | warn | medium | cleartext HTTP URL found in DEX strings: demo.testfire.net |
| dex.secret.aws_key.5c121b1092e4 | error | high | potential aws_key found in DEX string table |
| dex.webview.setAllowFileAccess.Lowasp.sat.agoat.InputValidationsWebViewURLActivity. | warn | high | WebView file access enabled — may allow reading local files (in Lowasp/sat/agoat/InputValidationsWebViewURLActivity;) |
| dex.webview.setAllowUniversalAccessFromFileURLs.Lowasp.sat.agoat.InputValidationsWebViewURLActivity. | error | high | WebView universal file access enabled — file:// URLs can access any origin (in Lowasp/sat/agoat/InputValidationsWebViewURLActivity;) |
```

</details>

#### JSON output

The default JSON output is a `ReportFile` with `schema_version`, `tool_version`, and `result`. An excerpt for AndroGoat:

```bash
$ mobilepkg inspect AndroGoat.apk | jq '{schema_version, identity: .result.identity, debuggable: .result.debuggable, finding: (.result.findings[] | select(.id=="manifest.debuggable"))}'
```

<details>
<summary>Output</summary>

```json
{
  "schema_version": "1.0.0",
  "identity": {
    "identifier": "owasp.sat.agoat",
    "display_name": "AndroGoat - Insecure App (Kotlin)"
  },
  "debuggable": true,
  "finding": {
    "id": "manifest.debuggable",
    "category": "manifest",
    "severity": "error",
    "confidence": "high",
    "message": "application is debuggable — allows arbitrary code execution via adb on any device",
    "evidence": [
      {
        "archive_path": "AndroidManifest.xml",
        "field": "application[@debuggable]"
      }
    ],
    "fingerprint": "cfdad16a5de2d41e"
  }
}
```

</details>

#### Baseline diff and CI

`--baseline` takes the JSON report of a previous `inspect` run:

```bash
# Save today's result
mobilepkg inspect app.apk > baseline.json

# Compare against baseline in CI
mobilepkg inspect --baseline baseline.json --fail-on warn app.apk
```

With `--fail-on`, the output has a `verdict` field with `passed`, `reasons`, and `triggering_findings`, and the command exits 1 when the policy fails.

### compare

```bash
$ mobilepkg compare old.apk new.apk
```

It prints identity, version and entry point changes, and the permissions, exported components and network endpoints that were added or removed.

## Library

### InspectFile

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

## Testing

| Technique | Bug class caught here |
|---|---|
| [Examples and unit tests](doc/testing.md#examples-and-unit-tests) | Wrong metadata or findings from the public API |
| [Generated properties](doc/testing.md#generated-properties) | Verdicts and diffs that break for some combination of findings |
| [Metamorphic relations](doc/testing.md#metamorphic-relations) | Results that change with input order or argument order |
| [Fuzzing](doc/testing.md#fuzzing) | Panics and unbounded allocation on malformed DEX, XML and resource tables |
| [CLI end-to-end tests](doc/testing.md#cli-end-to-end-tests) | Wrong exit codes, flags and messages of the binary |
| [Output snapshots](doc/testing.md#output-snapshots) | Unintended changes to the Markdown and JSON reports |
| [Mutation testing](doc/testing.md#mutation-testing) | Tests that still pass when a comparison or branch is changed |
| [Paired CI benchmarks](doc/testing.md#paired-ci-benchmarks) | Slower inspection hidden by runner noise |

## Test data

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

## Related projects

- [shogo82148/androidbinary](https://github.com/shogo82148/androidbinary): Android binary file parser written in golang
- [nao1215/deapk(already public archived)](https://github.com/nao1215/deapk): parse android package (.apk), getting meta data and more.

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/en/reference/emoji-key/)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://debimate.jp/"><img src="https://avatars.githubusercontent.com/u/22737008?v=4?s=75" width="75px;" alt="CHIKAMATSU Naohiro"/><br /><sub><b>CHIKAMATSU Naohiro</b></sub></a><br /><a href="https://github.com/nao1215/mobilepkg/commits?author=nao1215" title="Code">💻</a> <a href="https://github.com/nao1215/mobilepkg/commits?author=nao1215" title="Documentation">📖</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!

## License

[MIT License](LICENSE)
