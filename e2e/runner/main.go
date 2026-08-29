// Command runner bootstraps mobilepkg's end-to-end suite and hands the specs to
// atago.
//
// It builds mobilepkg from this checkout into a throwaway directory, puts that
// directory first on PATH so the specs exercise that exact binary, and runs the
// atago specs under e2e/atago.
//
// The test DEFINITIONS are the atago YAML; this program is only the environment
// bootstrap. It is Go rather than the shell script it replaces because the suite
// runs on Windows too, and a bash bootstrap would make the Windows leg depend on
// Git Bash being installed -- which tests the runner image rather than
// mobilepkg. Process launching, temp trees and PATH handling are things the
// standard library already does portably.
//
// mobilepkg is fully hermetic: it inspects a package file in-process, with no
// Android SDK, Xcode, device or network involved. The only committed fixture is
// the small intentionally-vulnerable AndroGoat APK, which the specs pull into
// their own workdir with atago `fixture` steps.
//
// Usage:
//
//	go run ./e2e/runner                  # every spec under e2e/atago
//	go run ./e2e/runner --filter inspect # extra flags are passed through to atago
//	COVER=1 GOCOVERDIR=... go run ./e2e/runner
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// fixture is the committed package every spec inspects. The runner checks for it
// up front so a missing fixture is one clear message rather than N failing
// scenarios.
var fixture = filepath.Join("testdata", "android", "androgoat_rich.apk")

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: %v\n", err)
		var exit *exitError
		if errors.As(err, &exit) {
			os.Exit(exit.code)
		}
		os.Exit(1)
	}
}

// exitError carries an exit status out of run, so a failing atago run exits with
// atago's own status instead of a generic 1. CI reads that status to tell "the
// suite failed" from "the bootstrap broke".
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func run(ctx context.Context, args []string) error {
	repoRoot, err := findRepoRoot()
	if err != nil {
		return err
	}

	if _, err := exec.LookPath("atago"); err != nil {
		return &exitError{code: 127, err: fmt.Errorf(
			"atago is not installed. Install it from https://github.com/nao1215/atago\n"+
				"e2e: e.g. 'go install github.com/nao1215/atago@latest' (CI uses nao1215/setup-atago): %w", err)}
	}
	if _, err := os.Stat(filepath.Join(repoRoot, fixture)); err != nil {
		return &exitError{code: 127, err: fmt.Errorf("committed fixture %s is missing: %w", fixture, err)}
	}

	tmp, err := os.MkdirTemp("", "mobilepkg-e2e-")
	if err != nil {
		return fmt.Errorf("can not create the e2e temp tree: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		return fmt.Errorf("can not create the e2e bin directory: %w", err)
	}

	binary := filepath.Join(binDir, "mobilepkg")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	if err := buildMobilepkg(ctx, repoRoot, binary); err != nil {
		return err
	}

	// Put the e2e-built mobilepkg first on PATH so the specs resolve to that
	// exact binary rather than one the developer happens to have installed.
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH")); err != nil {
		return fmt.Errorf("can not extend PATH: %w", err)
	}

	version, err := exec.CommandContext(ctx, binary, "version").Output() //nolint:gosec // the path is one this program just built
	if err != nil {
		return fmt.Errorf("can not run the freshly built mobilepkg: %w", err)
	}
	fmt.Printf("e2e: %s\n", strings.TrimSpace(firstLine(string(version))))

	// Extra args (e.g. --filter X) come before the path so atago's flag parser
	// sees them as flags rather than targets.
	atagoArgs := append([]string{"run"}, args...)
	if !hasTarget(args) {
		atagoArgs = append(atagoArgs, filepath.Join(repoRoot, "e2e", "atago"))
	}

	atago := exec.CommandContext(ctx, "atago", atagoArgs...) //nolint:gosec // a fixed command with author-supplied spec targets
	atago.Dir = repoRoot
	atago.Stdout = os.Stdout
	atago.Stderr = os.Stderr
	atago.Stdin = os.Stdin
	if err := atago.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return &exitError{code: exit.ExitCode(), err: fmt.Errorf("atago run failed: %w", err)}
		}
		return fmt.Errorf("can not run atago: %w", err)
	}
	return nil
}

// buildMobilepkg compiles the binary under test. COVER=1 (used by
// scripts/coverage.sh) builds a coverage-instrumented mobilepkg so the E2E run's
// covdata can be merged with unit coverage; the mobilepkg processes atago spawns
// inherit GOCOVERDIR and each writes raw covdata on exit. With COVER unset the
// build is a plain one, so `make e2e` stays a test of the shipped binary.
func buildMobilepkg(ctx context.Context, repoRoot, output string) error {
	fmt.Println("e2e: building mobilepkg...")

	buildArgs := []string{"build"}
	if os.Getenv("COVER") != "" {
		if os.Getenv("GOCOVERDIR") == "" {
			return errors.New("COVER=1 requires GOCOVERDIR to be set (see scripts/coverage.sh)")
		}
		buildArgs = append(buildArgs, "-cover", "-covermode=atomic", "-coverpkg=./...")
	}
	buildArgs = append(buildArgs, "-o", output, "./cmd/mobilepkg")

	cmd := exec.CommandContext(ctx, "go", buildArgs...)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("can not build mobilepkg: %w", err)
	}
	return nil
}

// findRepoRoot walks up from the working directory to the checkout root. go run
// compiles into a temp directory, so os.Executable is unreliable here; the
// module root is found by looking for go.mod above the current directory.
func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("can not determine the working directory: %w", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("can not find the repository root (no go.mod above the working directory)")
		}
		dir = parent
	}
}

// valueFlags are the `atago run` options that take their value as the NEXT
// argument. Without this list the runner cannot tell `--filter inspect` (a flag
// and its value) from `--filter` followed by a spec path, and would then skip
// adding the default target -- silently running nothing.
var valueFlags = map[string]bool{
	"artifacts-dir": true,
	"filter":        true,
	"parallel":      true,
	"profile":       true,
	"repeat":        true,
	"report":        true,
	"retry-failed":  true,
	"skip-tag":      true,
	"tag":           true,
}

// hasTarget reports whether the caller named spec files or directories of their
// own, as opposed to passing only atago flags.
func hasTarget(args []string) bool {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			return true
		}
		name := strings.TrimLeft(arg, "-")
		if strings.Contains(name, "=") {
			continue
		}
		if valueFlags[name] {
			i++
		}
	}
	return false
}

// firstLine returns everything before the first newline, so a multi-line version
// banner prints as one line.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
