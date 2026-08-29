# Contributing Guide

Thanks for your interest in mobilepkg. Bug reports, patches, tests, and reviews all help — this page covers the basics.

## Setting up

Go 1.25 or later is required (see the `go` directive in `go.mod`).

```bash
git clone https://github.com/nao1215/mobilepkg.git
cd mobilepkg
make tools    # install golangci-lint and atago
make test     # run unit tests
make e2e      # run the atago end-to-end suite against a freshly built binary
make lint     # run linter
make build    # build CLI binary
make coverage # combined unit + E2E coverage
```

The end-to-end tests live under `e2e/atago/` as plain-YAML [atago](https://github.com/nao1215/atago) specs and drive the real binary the way a user does (subcommand, flags, exit codes, JSON and Markdown output). `go run ./e2e/runner` builds mobilepkg from the checkout, puts it first on `PATH`, and hands the specs to atago, so the suite needs nothing installed system-wide.

The bootstrap is Go rather than a shell script because the suite runs on Windows too, where a bash bootstrap would only prove that Git for Windows is installed. For the same reason no spec uses `shell: true` or reads a host environment variable: fixtures arrive through atago `fixture` steps and output redirection through `stdout_to`.

## Branch naming

- `main` is the latest stable version.
- Create branches from `main`:
  - `feature/add-sbom-support`
  - `fix/issue-123`
  - `docs/update-readme`

## Coding standards

Follow [Effective Go](https://go.dev/doc/effective_go). In particular:

- No global variables. Pass state through arguments and return values.
- All public symbols (functions, types, fields) need doc comments.
- Each package gets a `doc.go` describing its purpose.
- Use `errors.Is` / `errors.As` for error checks. Don't swallow errors.
- Don't leave duplicate code behind — clean up after yourself.

## Tests

- Aim for 80 %+ coverage.
- Use `t.Run()` sub-tests and `t.Parallel()`.
- Use `github.com/stretchr/testify` (`assert` / `require`) for assertions.
- Join paths with `filepath.Join` so tests pass on Windows.
- Don't depend on files outside the repo. Build synthetic test data in helpers.

Example:

```go
func TestInspectFile_IPA(t *testing.T) {
    t.Parallel()

    dir := t.TempDir()
    ipaPath := createTestIPA(t, dir)

    t.Run("extracts identity from IPA", func(t *testing.T) {
        t.Parallel()
        report, err := mobilepkg.InspectFile(context.Background(), ipaPath, mobilepkg.InspectOptions{
            Sections: mobilepkg.SectionIdentity,
        })
        require.NoError(t, err)
        assert.Equal(t, "com.example.testapp", report.Identity.Identifier)
    })
}
```

## AI assistants

Using Claude Code, Copilot, Cursor, etc. is fine. Just review the output, make sure it follows the standards above, and confirm `make test && make lint` passes before committing.

## Pull requests

1. Check existing issues first. For larger changes, open an issue to discuss direction before writing code.
2. Add tests for new features. For bug fixes, add a test that reproduces the bug.
3. Run `make test`, `make lint`, and `make e2e` for changes visible from the command line, and check coverage (`make coverage`).
4. PR title: brief summary. PR body: what changed, why, related issue number, and how to test.

CI runs the following checks automatically — PRs cannot be merged until they all pass:

- Cross-platform unit tests (Linux, macOS, Windows)
- Cross-platform atago end-to-end tests (Linux, macOS, Windows)
- golangci-lint via reviewdog
- Coverage reporting via octocov (80 %+)
- Build verification (`make build`)
- gitleaks secret scanning

## Bug reports

Open an issue with:

- OS and version, Go version, mobilepkg version (`mobilepkg version`)
- Minimal reproduction steps (command or code)
- Expected vs. actual behavior
- Error messages or stack traces if available

## Other ways to help

- Star the repo
- Share it in a blog post, talk, or study group
- Improve docs, fix typos, add examples
- Suggest features in issues
- [Sponsor the project](https://github.com/sponsors/nao1215)

## License

Contributions are released under the project's [MIT License](LICENSE).
