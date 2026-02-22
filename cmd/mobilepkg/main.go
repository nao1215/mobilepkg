// mobilepkg is a CLI tool for inspecting mobile application packages.
//
// Usage:
//
//	mobilepkg <command> [flags] <file>
//
// Commands:
//
//	inspect   Inspect a mobile package (facts + findings)
//	compare   Compare two package files
//	version   Print the version
//
// Examples:
//
//	mobilepkg inspect app.apk
//	mobilepkg inspect --format markdown app.apk
//	mobilepkg inspect --baseline baseline.json app.apk
//	mobilepkg inspect --fail-on warn app.apk
//	mobilepkg compare old.apk new.apk
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/nao1215/mobilepkg"
	"github.com/nao1215/mobilepkg/internal/cmdinfo"
)

const usage = `mobilepkg — inspect mobile application packages (APK/IPA/XAPK/APKS/AAB)

Usage:
  mobilepkg <command> [flags] <file...>

Commands:
  inspect          Inspect a mobile package (facts + findings)
  compare (diff)   Compare two package files
  version          Print the version

Run "mobilepkg <command> -h" for command-specific help.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "inspect":
		err = runInspect(args)
	case "compare", "diff":
		err = runCompare(args)
	case "version", "--version", "-v":
		fmt.Printf("mobilepkg %s\n", cmdinfo.GetVersion())
		return
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "mobilepkg: unknown command %q\n\n%s", cmd, usage)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "mobilepkg %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

// runInspect performs a full inspection on a package file: extracting
// metadata, running security analysis, and outputting the result.
//
// When --fail-on is specified, the command also evaluates fail conditions
// and exits with code 1 if any finding meets the threshold.
func runInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	baselinePath := fs.String("baseline", "", "path to a baseline report.json for comparison")
	formatFlag := fs.String("format", "json", "output format: json or markdown")
	failOn := fs.String("fail-on", "", "exit 1 if any finding has severity >= this value (info, warn, error)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: mobilepkg inspect [flags] <file>

Inspect a mobile application package. Extracts metadata, runs security
analysis, and outputs the result in the specified format (default: json).

When --fail-on is specified, exits with code 1 if any finding meets the
severity threshold. This is useful for CI pipelines:

  mobilepkg inspect --fail-on warn app.apk > report.json

Flags:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}

	ctx := context.Background()

	var result *mobilepkg.InspectResult
	var err error

	if *baselinePath != "" {
		baselineFile, openErr := os.Open(*baselinePath)
		if openErr != nil {
			return fmt.Errorf("opening baseline: %w", openErr)
		}
		defer func() { _ = baselineFile.Close() }()

		rf, loadErr := mobilepkg.LoadReportFile(baselineFile)
		if loadErr != nil {
			return fmt.Errorf("loading baseline: %w", loadErr)
		}

		result, err = mobilepkg.InspectWithBaseline(ctx, fs.Arg(0), &rf.Result)
	} else {
		result, err = mobilepkg.InspectFile(ctx, fs.Arg(0))
	}
	if err != nil {
		return err
	}

	// Build the report file.
	rf := mobilepkg.NewReportFile(result, cmdinfo.GetVersion())

	// Evaluate fail conditions and include verdict in output.
	exitCode := 0
	if *failOn != "" {
		policy := mobilepkg.FailPolicy{
			FailOnSeverity: mobilepkg.Severity(*failOn),
		}
		verdict := mobilepkg.Check(result, policy)
		rf.Verdict = &verdict
		if !verdict.Passed {
			exitCode = 1
		}
	}

	// Output the result.
	switch strings.ToLower(*formatFlag) {
	case "json":
		if err := mobilepkg.WriteReportJSON(os.Stdout, rf); err != nil {
			return err
		}
	case "markdown", "md":
		if err := mobilepkg.WriteSummaryMarkdown(os.Stdout, rf); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown format %q (valid: json, markdown)", *formatFlag)
	}

	if exitCode != 0 {
		os.Exit(exitCode)
	}
	return nil
}

// runCompare compares two packages.
func runCompare(args []string) error {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: mobilepkg compare <old-file> <new-file>

Compare two mobile application packages and show differences.
Output is JSON.

`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		fs.Usage()
		os.Exit(1)
	}

	ctx := context.Background()

	oldResult, err := mobilepkg.InspectFile(ctx, fs.Arg(0))
	if err != nil {
		return fmt.Errorf("old file: %w", err)
	}

	newResult, err := mobilepkg.InspectFile(ctx, fs.Arg(1))
	if err != nil {
		return fmt.Errorf("new file: %w", err)
	}

	diff := mobilepkg.Compare(oldResult, newResult)

	return printJSON(buildDiffOutput(diff, oldResult, newResult))
}

type diffOutput struct {
	OldPlatform        string                        `json:"old_platform"`
	NewPlatform        string                        `json:"new_platform"`
	OldFormat          string                        `json:"old_format"`
	NewFormat          string                        `json:"new_format"`
	IdentityChanged    bool                          `json:"identity_changed"`
	VersionChanged     bool                          `json:"version_changed"`
	EntryChanged       bool                          `json:"entry_changed"`
	OldIdentity        *identityOutput               `json:"old_identity,omitempty"`
	NewIdentity        *identityOutput               `json:"new_identity,omitempty"`
	OldVersion         *versionOutput                `json:"old_version,omitempty"`
	NewVersion         *versionOutput                `json:"new_version,omitempty"`
	AddedPermissions   []permissionOutput            `json:"added_permissions,omitempty"`
	RemovedPermissions []permissionOutput            `json:"removed_permissions,omitempty"`
	AddedComponents    []mobilepkg.ExportedComponent `json:"added_components,omitempty"`
	RemovedComponents  []mobilepkg.ExportedComponent `json:"removed_components,omitempty"`
	AddedEndpoints     []mobilepkg.NetworkEndpoint   `json:"added_endpoints,omitempty"`
	RemovedEndpoints   []mobilepkg.NetworkEndpoint   `json:"removed_endpoints,omitempty"`
}

type identityOutput struct {
	Identifier  string `json:"identifier"`
	DisplayName string `json:"display_name"`
}

type versionOutput struct {
	Marketing string `json:"marketing"`
	Build     string `json:"build"`
}

type permissionOutput struct {
	Canonical string `json:"canonical,omitempty"`
	RawName   string `json:"raw_name"`
	Source    string `json:"source"`
}

func buildDiffOutput(d mobilepkg.Diff, oldIR, newIR *mobilepkg.InspectResult) diffOutput {
	out := diffOutput{
		OldPlatform:     string(d.OldPlatform),
		NewPlatform:     string(d.NewPlatform),
		OldFormat:       string(oldIR.Format),
		NewFormat:       string(newIR.Format),
		IdentityChanged: d.IdentityChanged,
		VersionChanged:  d.VersionChanged,
		EntryChanged:    d.EntryChanged,
	}

	if d.IdentityChanged {
		out.OldIdentity = &identityOutput{
			Identifier:  oldIR.Identity.Identifier,
			DisplayName: oldIR.Identity.DisplayName,
		}
		out.NewIdentity = &identityOutput{
			Identifier:  newIR.Identity.Identifier,
			DisplayName: newIR.Identity.DisplayName,
		}
	}

	if d.VersionChanged {
		out.OldVersion = &versionOutput{
			Marketing: oldIR.Version.Marketing,
			Build:     oldIR.Version.Build,
		}
		out.NewVersion = &versionOutput{
			Marketing: newIR.Version.Marketing,
			Build:     newIR.Version.Build,
		}
	}

	for _, p := range d.AddedPermissions {
		out.AddedPermissions = append(out.AddedPermissions, permissionOutput{
			Canonical: p.Canonical,
			RawName:   p.RawName,
			Source:    p.Source,
		})
	}
	for _, p := range d.RemovedPermissions {
		out.RemovedPermissions = append(out.RemovedPermissions, permissionOutput{
			Canonical: p.Canonical,
			RawName:   p.RawName,
			Source:    p.Source,
		})
	}

	out.AddedComponents = d.AddedComponents
	out.RemovedComponents = d.RemovedComponents
	out.AddedEndpoints = d.AddedEndpoints
	out.RemovedEndpoints = d.RemovedEndpoints

	return out
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
