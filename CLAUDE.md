# mobilepkg

mobilepkg is a Go library that provides a unified API for inspecting Android (APK) and iOS (IPA) mobile application packages. It abstracts platform-specific differences so that users can perform common operational tasks — CI quality gates, catalog data extraction, security audits, and release diff checks — with a single set of API calls.

The library is based on [shogo82148/androidbinary](https://github.com/shogo82148/androidbinary) (bundled under `doc/androidbinary` for reference) and extends it with iOS support and a higher-level, task-oriented interface.

## Codebase Information
### Development Commands
- `make test`: Run tests and measure coverage (generates cover.out file, viewable in browser with cover.html)
- `make lint`: Code inspection with golangci-lint (.golangci.yml configuration)
- `make clean`: Delete generated files
- `make tools`: Install dependency tools (golangci-lint, octocov)

### Key Features
- **Probe**: Lightweight file-type detection (APK vs IPA) without full parsing
- **Inspect**: Unified report extraction (identity, version, entry point, permissions, icon) from APK/IPA
- **Diff**: Structured comparison of two reports to detect changes between releases
- **Section-based loading**: Callers choose which sections to parse via bitmask (`SectionIdentity`, `SectionVersion`, etc.)
- **Partial success model**: Non-fatal issues are reported as `Diagnostics` in the report rather than hard errors

### Architecture
```
mobilepkg (public API)
  ProbeFile / InspectFile / DiffReports
            |
            v
  detector/router (APK / IPA detection)
            |
    +-------+-------+
    |               |
  android adapter   ios adapter
  (apk parser)      (Info.plist / entitlements)
    |               |
    +-------+-------+
            v
      report normalizer
```

### Directory Structure
```
/mobilepkg
  doc.go         # package documentation
  types.go       # core types (Report, Identity, Version, Permission, etc.)
  errors.go      # error and diagnostic types
  probe.go       # ProbeFile implementation
  inspect.go     # InspectFile and DiffReports
  diff.go        # DiffReports implementation

/internal/platform/android
  doc.go         # package documentation
  inspect.go     # Android-specific inspection using apk parser

/internal/platform/ios
  doc.go         # package documentation
  inspect.go     # iOS-specific inspection (Info.plist, entitlements)
```

## Development Rules
- Test-Driven Development: We adopt the test-driven development promoted by t-wada (Takuto Wada). Always write test code and be mindful of the test pyramid.
- Working code: Ensure that `make test` and `make lint` succeed after completing work.
- Sponsor acquisition: Since development incurs financial costs, we seek sponsors via `https://github.com/sponsors/nao1215`. Include sponsor links in README and documentation.
- Contributor acquisition: Create developer documentation so anyone can participate in development and recruit contributors.
- Comments in English: Write code comments in English to accept international contributors.
- User-friendly documentation comments: Write detailed explanations and example code for public functions so users can understand usage at a glance.

## Coding Guidelines
- No global variables: Do not use global variables. Manage state through function arguments and return values.
- Coding rules: Follow Golang coding rules. [Effective Go](https://go.dev/doc/effective_go) is the basic rule.
- Package comments are mandatory: Describe the package overview in `doc.go` for each package. Clarify the purpose and usage of the package.
- Comments for public functions, variables, and struct fields are mandatory: When visibility is public, always write comments following go doc rules.
- Remove duplicate code: After completing your work, check if you have created duplicate code and remove unnecessary code.
- Error handling: Use `errors.Is` and `errors.As` for error interface equality checks. Never omit error handling.
- Documentation comments: Write documentation comments to help users understand how to use the code. In-code comments should explain why or why not something is done.

## Testing
- [Readable Test Code](https://logmi.jp/main/technology/327449): Avoid excessive optimization (DRY) and aim for a state where it's easy to understand what tests exist.
- Clear input/output: Create tests with `t.Run()` and clarify test case input/output. Test cases clarify test intent by explicitly showing input and expected output.
- Test descriptions: The first argument of `t.Run()` should clearly describe the relationship between input and expected output.
- Test granularity: Aim for 80% or higher coverage with unit tests.
- Parallel test execution: Use `t.Parallel()` to run tests in parallel whenever possible.
- Cross-platform support: Tests run on Linux, macOS, and Windows through GitHub Actions.
- Test data storage: Store sample files (APK, IPA) in the testdata directory.
