package main

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nao1215/mobilepkg"
	"howett.net/plist"
)

func TestRunInspect(t *testing.T) {
	dir := t.TempDir()
	ipaPath := createCLIIPA(t, dir, cliIPASpec{
		fileName:    "inspect.ipa",
		bundleID:    "com.example.inspect",
		displayName: "Inspect App",
		version:     "1.0.0",
		build:       "1",
		permissions: []string{"NSCameraUsageDescription"},
	})

	jsonOutput := captureStdout(t, func() {
		if err := runInspect([]string{"-format", "json", ipaPath}); err != nil {
			t.Fatalf("runInspect(json): %v", err)
		}
	})
	if !strings.Contains(jsonOutput, `"platform": "ios"`) {
		t.Fatalf("json output = %q", jsonOutput)
	}

	markdownOutput := captureStdout(t, func() {
		if err := runInspect([]string{"-format", "markdown", ipaPath}); err != nil {
			t.Fatalf("runInspect(markdown): %v", err)
		}
	})
	if !strings.Contains(markdownOutput, "mobilepkg Inspection Report") {
		t.Fatalf("markdown output = %q", markdownOutput)
	}

	result, err := mobilepkg.InspectFile(context.Background(), ipaPath)
	if err != nil {
		t.Fatalf("InspectFile: %v", err)
	}
	baselinePath := filepath.Join(dir, "baseline.json")
	baselineFile, err := os.Create(baselinePath)
	if err != nil {
		t.Fatalf("Create baseline: %v", err)
	}
	if err := mobilepkg.WriteReportJSON(baselineFile, mobilepkg.NewReportFile(result, "test")); err != nil {
		_ = baselineFile.Close()
		t.Fatalf("WriteReportJSON: %v", err)
	}
	if err := baselineFile.Close(); err != nil {
		t.Fatalf("Close baseline: %v", err)
	}

	baselineOutput := captureStdout(t, func() {
		if err := runInspect([]string{"-baseline", baselinePath, "-format", "json", ipaPath}); err != nil {
			t.Fatalf("runInspect(baseline): %v", err)
		}
	})
	if !strings.Contains(baselineOutput, `"diff":`) {
		t.Fatalf("baseline output = %q", baselineOutput)
	}

	if err := runInspect([]string{"-format", "yaml", ipaPath}); err == nil {
		t.Fatal("runInspect(unknown format) error = nil")
	}
}

func TestRunCompareAndBuildDiffOutput(t *testing.T) {
	dir := t.TempDir()
	oldPath := createCLIIPA(t, dir, cliIPASpec{
		fileName:    "old.ipa",
		bundleID:    "com.example.old",
		displayName: "Old App",
		version:     "1.0.0",
		build:       "1",
		permissions: []string{"NSCameraUsageDescription"},
	})
	newPath := createCLIIPA(t, dir, cliIPASpec{
		fileName:    "new.ipa",
		bundleID:    "com.example.new",
		displayName: "New App",
		version:     "2.0.0",
		build:       "2",
		permissions: []string{"NSCameraUsageDescription", "NSLocationWhenInUseUsageDescription"},
	})

	output := captureStdout(t, func() {
		if err := runCompare([]string{oldPath, newPath}); err != nil {
			t.Fatalf("runCompare: %v", err)
		}
	})
	if !strings.Contains(output, `"identity_changed": true`) || !strings.Contains(output, `"version_changed": true`) {
		t.Fatalf("compare output = %q", output)
	}
	if !strings.Contains(output, `"raw_name": "NSLocationWhenInUseUsageDescription"`) {
		t.Fatalf("compare output missing added permission: %q", output)
	}

	oldIR := &mobilepkg.InspectResult{
		Platform: mobilepkg.PlatformIOS,
		Format:   mobilepkg.FormatIPA,
		Identity: mobilepkg.Identity{Identifier: "old.id", DisplayName: "Old"},
		Version:  mobilepkg.Version{Marketing: "1.0.0", Build: "1"},
	}
	newIR := &mobilepkg.InspectResult{
		Platform: mobilepkg.PlatformIOS,
		Format:   mobilepkg.FormatIPA,
		Identity: mobilepkg.Identity{Identifier: "new.id", DisplayName: "New"},
		Version:  mobilepkg.Version{Marketing: "2.0.0", Build: "2"},
	}
	diff := mobilepkg.Diff{
		OldPlatform:     mobilepkg.PlatformIOS,
		NewPlatform:     mobilepkg.PlatformIOS,
		IdentityChanged: true,
		VersionChanged:  true,
		EntryChanged:    true,
		AddedPermissions: []mobilepkg.Permission{
			{Canonical: "camera", RawName: "NSCameraUsageDescription", Source: "info_plist"},
		},
		RemovedPermissions: []mobilepkg.Permission{
			{Canonical: "location", RawName: "NSLocationWhenInUseUsageDescription", Source: "info_plist"},
		},
	}
	got := buildDiffOutput(diff, oldIR, newIR)
	if got.OldIdentity == nil || got.NewIdentity == nil || got.OldVersion == nil || got.NewVersion == nil {
		t.Fatalf("buildDiffOutput missing identity/version data: %#v", got)
	}
	if len(got.AddedPermissions) != 1 || len(got.RemovedPermissions) != 1 {
		t.Fatalf("buildDiffOutput permissions = %#v", got)
	}
}

func TestPrintJSONAndMain(t *testing.T) {
	jsonOutput := captureStdout(t, func() {
		if err := printJSON(map[string]string{"hello": "world"}); err != nil {
			t.Fatalf("printJSON: %v", err)
		}
	})
	if !strings.Contains(jsonOutput, `"hello": "world"`) {
		t.Fatalf("printJSON output = %q", jsonOutput)
	}

	dir := t.TempDir()
	ipaPath := createCLIIPA(t, dir, cliIPASpec{
		fileName:    "main.ipa",
		bundleID:    "com.example.main",
		displayName: "Main App",
		version:     "1.0.0",
		build:       "1",
		permissions: []string{"NSCameraUsageDescription"},
	})
	otherPath := createCLIIPA(t, dir, cliIPASpec{
		fileName:    "other.ipa",
		bundleID:    "com.example.other",
		displayName: "Other App",
		version:     "2.0.0",
		build:       "2",
		permissions: []string{"NSCameraUsageDescription", "NSLocationWhenInUseUsageDescription"},
	})

	withArgs(t, []string{"mobilepkg", "version"}, func() {
		output := captureStdout(t, main)
		if !strings.Contains(output, "mobilepkg ") {
			t.Fatalf("version output = %q", output)
		}
	})

	withArgs(t, []string{"mobilepkg", "help"}, func() {
		output := captureStdout(t, main)
		if !strings.Contains(output, "Usage:") {
			t.Fatalf("help output = %q", output)
		}
	})

	withArgs(t, []string{"mobilepkg", "inspect", "-format", "json", ipaPath}, func() {
		output := captureStdout(t, main)
		if !strings.Contains(output, `"platform": "ios"`) {
			t.Fatalf("inspect output = %q", output)
		}
	})

	withArgs(t, []string{"mobilepkg", "compare", ipaPath, otherPath}, func() {
		output := captureStdout(t, main)
		if !strings.Contains(output, `"version_changed": true`) {
			t.Fatalf("compare output = %q", output)
		}
	})
}

type cliIPASpec struct {
	fileName    string
	bundleID    string
	displayName string
	version     string
	build       string
	permissions []string
}

func createCLIIPA(t *testing.T, dir string, spec cliIPASpec) string {
	t.Helper()

	path := filepath.Join(dir, spec.fileName)
	infoPlist := map[string]any{
		"CFBundleIdentifier":         spec.bundleID,
		"CFBundleDisplayName":        spec.displayName,
		"CFBundleShortVersionString": spec.version,
		"CFBundleVersion":            spec.build,
		"CFBundleExecutable":         "TestApp",
	}
	for _, key := range spec.permissions {
		infoPlist[key] = key + " reason"
	}

	plistData, err := plist.MarshalIndent(infoPlist, plist.XMLFormat, "\t")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("Payload/TestApp.app/Info.plist")
	if err != nil {
		t.Fatalf("Create Info.plist: %v", err)
	}
	if _, err := w.Write(plistData); err != nil {
		t.Fatalf("Write Info.plist: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("Close zip: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
	return path
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		_ = r.Close()
		done <- buf.String()
	}()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("Close stdout pipe: %v", err)
	}
	return <-done
}

func withArgs(t *testing.T, args []string, fn func()) {
	t.Helper()

	orig := os.Args
	os.Args = args
	defer func() { os.Args = orig }()
	fn()
}
