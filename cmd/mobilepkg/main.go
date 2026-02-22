// mobilepkg is a CLI tool for inspecting mobile application packages.
//
// Usage:
//
//	mobilepkg <command> [flags] <file>
//
// Commands:
//
//	probe     Detect the platform and format of a package file.
//	inspect   Extract detailed information from a package file.
//	diff      Compare two package files and show differences.
//
// Examples:
//
//	mobilepkg probe app.apk
//	mobilepkg inspect app.ipa
//	mobilepkg inspect -sections identity,version app.apk
//	mobilepkg inspect -icon-out icon.png app.apk
//	mobilepkg diff old.apk new.apk
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/nao1215/mobilepkg"
)

const usage = `mobilepkg — inspect mobile application packages (APK/IPA/XAPK/APKS/AAB)

Usage:
  mobilepkg <command> [flags] <file>

Commands:
  probe     Detect the platform and format of a package file
  inspect   Extract detailed information from a package file
  diff      Compare two package files and show differences

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
	case "probe":
		err = runProbe(args)
	case "inspect":
		err = runInspect(args)
	case "diff":
		err = runDiff(args)
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

// runProbe detects platform and format.
func runProbe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: mobilepkg probe <file>

Detect the platform and format of a mobile application package.
Output is JSON.
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}

	result, err := mobilepkg.ProbeFile(fs.Arg(0))
	if err != nil {
		return err
	}

	return printJSON(probeOutput{
		Platform:  string(result.Platform),
		Format:    string(result.Format),
		Container: result.Container,
		Hints:     result.Hints,
	})
}

type probeOutput struct {
	Platform  string   `json:"platform"`
	Format    string   `json:"format"`
	Container string   `json:"container"`
	Hints     []string `json:"hints"`
}

// runInspect extracts package information.
func runInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	sectionsFlag := fs.String("sections", "all", "comma-separated sections: identity,version,entry,permissions,icon,raw,sdk,signing,all")
	iconOut := fs.String("icon-out", "", "write extracted icon to this file path")
	iconSize := fs.Int("icon-size", 0, "preferred icon size in pixels (AAB only)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: mobilepkg inspect [flags] <file>

Extract detailed information from a mobile application package.
Output is JSON.

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

	sections, err := parseSections(*sectionsFlag)
	if err != nil {
		return err
	}

	// -icon-out implies SectionIcon so the icon is always extracted.
	if *iconOut != "" {
		sections |= mobilepkg.SectionIcon
	}

	opts := mobilepkg.InspectOptions{
		Sections: sections,
		Icon:     mobilepkg.IconOptions{SizePx: *iconSize},
	}

	report, err := mobilepkg.InspectFile(context.Background(), fs.Arg(0), opts)
	if err != nil {
		return err
	}

	// Write icon to file if requested.
	if *iconOut != "" {
		if report.Icon != nil && len(report.Icon.Bytes) > 0 {
			if err := os.WriteFile(*iconOut, report.Icon.Bytes, 0o644); err != nil {
				return fmt.Errorf("writing icon: %w", err)
			}
			fmt.Fprintf(os.Stderr, "icon written to %s (%dx%d, %s)\n",
				*iconOut, report.Icon.Width, report.Icon.Height, report.Icon.Format)
		} else {
			return fmt.Errorf("no icon available in package; cannot write to %s", *iconOut)
		}
	}

	return printJSON(buildInspectOutput(report))
}

type inspectOutput struct {
	Platform    string              `json:"platform"`
	Format      string              `json:"format"`
	Identity    *identityOutput     `json:"identity,omitempty"`
	Version     *versionOutput      `json:"version,omitempty"`
	Entry       *entryOutput        `json:"entry,omitempty"`
	Permissions []permissionOutput  `json:"permissions,omitempty"`
	SDK         *sdkOutput          `json:"sdk,omitempty"`
	Signing     *signingOutput      `json:"signing,omitempty"`
	Icon        *iconOutput         `json:"icon,omitempty"`
	Diagnostics []diagnosticOutput  `json:"diagnostics,omitempty"`
	Android     *androidRawOutput   `json:"android,omitempty"`
	IOS         *iosRawOutput       `json:"ios,omitempty"`
}

type sdkOutput struct {
	MinSDK    string `json:"min_sdk,omitempty"`
	TargetSDK string `json:"target_sdk,omitempty"`
}

type signingOutput struct {
	Scheme       string           `json:"scheme"`
	Certificates []certOutput     `json:"certificates,omitempty"`
}

type certOutput struct {
	Subject           string `json:"subject"`
	Issuer            string `json:"issuer"`
	NotBefore         string `json:"not_before"`
	NotAfter          string `json:"not_after"`
	SHA256Fingerprint string `json:"sha256_fingerprint"`
	SerialNumber      string `json:"serial_number"`
}

type identityOutput struct {
	Identifier  string `json:"identifier"`
	DisplayName string `json:"display_name"`
}

type versionOutput struct {
	Marketing string `json:"marketing"`
	Build     string `json:"build"`
}

type entryOutput struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type permissionOutput struct {
	Canonical string `json:"canonical,omitempty"`
	RawName   string `json:"raw_name"`
	Source    string `json:"source"`
}

type iconOutput struct {
	Path   string `json:"path"`
	Format string `json:"format"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Size   int    `json:"size_bytes"`
}

type diagnosticOutput struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type androidRawOutput struct {
	Manifest map[string]any `json:"manifest,omitempty"`
}

type iosRawOutput struct {
	InfoPlist    map[string]any `json:"info_plist,omitempty"`
	Entitlements map[string]any `json:"entitlements,omitempty"`
}

func buildInspectOutput(r mobilepkg.Report) inspectOutput {
	out := inspectOutput{
		Platform: string(r.Platform),
		Format:   string(r.Format),
	}

	if r.Identity != (mobilepkg.Identity{}) {
		out.Identity = &identityOutput{
			Identifier:  r.Identity.Identifier,
			DisplayName: r.Identity.DisplayName,
		}
	}

	if r.Version != (mobilepkg.Version{}) {
		out.Version = &versionOutput{
			Marketing: r.Version.Marketing,
			Build:     r.Version.Build,
		}
	}

	if r.Entry != (mobilepkg.EntryPoint{}) {
		out.Entry = &entryOutput{
			Kind: r.Entry.Kind,
			Name: r.Entry.Name,
		}
	}

	for _, p := range r.Permissions {
		out.Permissions = append(out.Permissions, permissionOutput{
			Canonical: p.Canonical,
			RawName:   p.RawName,
			Source:    p.Source,
		})
	}

	if r.SDK != (mobilepkg.SDKConstraints{}) {
		out.SDK = &sdkOutput{
			MinSDK:    r.SDK.MinSDK,
			TargetSDK: r.SDK.TargetSDK,
		}
	}

	if r.Signing != nil {
		so := &signingOutput{Scheme: r.Signing.Scheme}
		for _, c := range r.Signing.Certificates {
			so.Certificates = append(so.Certificates, certOutput{
				Subject:           c.Subject,
				Issuer:            c.Issuer,
				NotBefore:         c.NotBefore,
				NotAfter:          c.NotAfter,
				SHA256Fingerprint: c.SHA256Fingerprint,
				SerialNumber:      c.SerialNumber,
			})
		}
		out.Signing = so
	}

	if r.Icon != nil {
		out.Icon = &iconOutput{
			Path:   r.Icon.Path,
			Format: r.Icon.Format,
			Width:  r.Icon.Width,
			Height: r.Icon.Height,
			Size:   len(r.Icon.Bytes),
		}
	}

	for _, d := range r.Diagnostics {
		out.Diagnostics = append(out.Diagnostics, diagnosticOutput{
			Code:     d.Code,
			Severity: string(d.Severity),
			Message:  d.Message,
		})
	}

	if ar, ok := mobilepkg.AsAndroid(r); ok {
		out.Android = &androidRawOutput{Manifest: ar.RawManifest}
	}
	if ir, ok := mobilepkg.AsIOS(r); ok {
		out.IOS = &iosRawOutput{
			InfoPlist:    ir.InfoPlist,
			Entitlements: ir.Entitlements,
		}
	}

	return out
}

// runDiff compares two packages.
func runDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	sectionsFlag := fs.String("sections", "all", "comma-separated sections to compare")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: mobilepkg diff [flags] <old-file> <new-file>

Compare two mobile application packages and show differences.
Output is JSON.

Flags:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		fs.Usage()
		os.Exit(1)
	}

	sections, err := parseSections(*sectionsFlag)
	if err != nil {
		return err
	}

	ctx := context.Background()
	opts := mobilepkg.InspectOptions{Sections: sections}

	oldReport, err := mobilepkg.InspectFile(ctx, fs.Arg(0), opts)
	if err != nil {
		return fmt.Errorf("old file: %w", err)
	}

	newReport, err := mobilepkg.InspectFile(ctx, fs.Arg(1), opts)
	if err != nil {
		return fmt.Errorf("new file: %w", err)
	}

	diff := mobilepkg.DiffReports(oldReport, newReport)

	return printJSON(buildDiffOutput(diff, oldReport, newReport))
}

type diffOutput struct {
	OldPlatform        string             `json:"old_platform"`
	NewPlatform        string             `json:"new_platform"`
	OldFormat          string             `json:"old_format"`
	NewFormat          string             `json:"new_format"`
	IdentityChanged    bool               `json:"identity_changed"`
	VersionChanged     bool               `json:"version_changed"`
	EntryChanged       bool               `json:"entry_changed"`
	OldIdentity        *identityOutput    `json:"old_identity,omitempty"`
	NewIdentity        *identityOutput    `json:"new_identity,omitempty"`
	OldVersion         *versionOutput     `json:"old_version,omitempty"`
	NewVersion         *versionOutput     `json:"new_version,omitempty"`
	AddedPermissions   []permissionOutput `json:"added_permissions,omitempty"`
	RemovedPermissions []permissionOutput `json:"removed_permissions,omitempty"`
}

func buildDiffOutput(d mobilepkg.Diff, oldR, newR mobilepkg.Report) diffOutput {
	out := diffOutput{
		OldPlatform:     string(d.OldPlatform),
		NewPlatform:     string(d.NewPlatform),
		OldFormat:       string(oldR.Format),
		NewFormat:       string(newR.Format),
		IdentityChanged: d.IdentityChanged,
		VersionChanged:  d.VersionChanged,
		EntryChanged:    d.EntryChanged,
	}

	if d.IdentityChanged {
		out.OldIdentity = &identityOutput{
			Identifier:  oldR.Identity.Identifier,
			DisplayName: oldR.Identity.DisplayName,
		}
		out.NewIdentity = &identityOutput{
			Identifier:  newR.Identity.Identifier,
			DisplayName: newR.Identity.DisplayName,
		}
	}

	if d.VersionChanged {
		out.OldVersion = &versionOutput{
			Marketing: oldR.Version.Marketing,
			Build:     oldR.Version.Build,
		}
		out.NewVersion = &versionOutput{
			Marketing: newR.Version.Marketing,
			Build:     newR.Version.Build,
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

	return out
}

// parseSections converts a comma-separated section list into a bitmask.
func parseSections(s string) (mobilepkg.Section, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "all" {
		return mobilepkg.SectionAll, nil
	}

	var sections mobilepkg.Section
	for _, name := range strings.Split(s, ",") {
		name = strings.TrimSpace(strings.ToLower(name))
		switch name {
		case "identity":
			sections |= mobilepkg.SectionIdentity
		case "version":
			sections |= mobilepkg.SectionVersion
		case "entry":
			sections |= mobilepkg.SectionEntryPoint
		case "permissions":
			sections |= mobilepkg.SectionPermissions
		case "icon":
			sections |= mobilepkg.SectionIcon
		case "raw":
			sections |= mobilepkg.SectionPlatformRaw
		case "sdk":
			sections |= mobilepkg.SectionSDK
		case "signing":
			sections |= mobilepkg.SectionSigning
		case "all":
			sections |= mobilepkg.SectionAll
		default:
			return 0, fmt.Errorf("unknown section %q (valid: identity,version,entry,permissions,icon,raw,sdk,signing,all)", name)
		}
	}

	return sections, nil
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
