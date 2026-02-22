package mobilepkg_test

import (
	"testing"

	"github.com/nao1215/mobilepkg"
)

func TestDiffReports(t *testing.T) {
	t.Parallel()

	t.Run("detects no changes for identical reports", func(t *testing.T) {
		t.Parallel()
		report := mobilepkg.Report{
			Platform: mobilepkg.PlatformAndroid,
			Identity: mobilepkg.Identity{
				Identifier:  "com.example.app",
				DisplayName: "My App",
			},
			Version: mobilepkg.Version{
				Marketing: "1.0.0",
				Build:     "1",
			},
			Permissions: []mobilepkg.Permission{
				{RawName: "android.permission.CAMERA", Source: "manifest"},
			},
		}

		diff := mobilepkg.DiffReports(report, report)
		if diff.IdentityChanged {
			t.Error("IdentityChanged should be false for identical reports")
		}
		if diff.VersionChanged {
			t.Error("VersionChanged should be false for identical reports")
		}
		if diff.EntryChanged {
			t.Error("EntryChanged should be false for identical reports")
		}
		if len(diff.AddedPermissions) != 0 {
			t.Errorf("AddedPermissions = %d, want 0", len(diff.AddedPermissions))
		}
		if len(diff.RemovedPermissions) != 0 {
			t.Errorf("RemovedPermissions = %d, want 0", len(diff.RemovedPermissions))
		}
	})

	t.Run("detects version change", func(t *testing.T) {
		t.Parallel()
		oldReport := mobilepkg.Report{
			Version: mobilepkg.Version{Marketing: "1.0.0", Build: "1"},
		}
		newReport := mobilepkg.Report{
			Version: mobilepkg.Version{Marketing: "2.0.0", Build: "2"},
		}

		diff := mobilepkg.DiffReports(oldReport, newReport)
		if !diff.VersionChanged {
			t.Error("VersionChanged should be true")
		}
	})

	t.Run("detects identity change", func(t *testing.T) {
		t.Parallel()
		oldReport := mobilepkg.Report{
			Identity: mobilepkg.Identity{Identifier: "com.old.app"},
		}
		newReport := mobilepkg.Report{
			Identity: mobilepkg.Identity{Identifier: "com.new.app"},
		}

		diff := mobilepkg.DiffReports(oldReport, newReport)
		if !diff.IdentityChanged {
			t.Error("IdentityChanged should be true")
		}
	})

	t.Run("detects added permissions", func(t *testing.T) {
		t.Parallel()
		oldReport := mobilepkg.Report{
			Permissions: []mobilepkg.Permission{
				{RawName: "android.permission.CAMERA", Source: "manifest"},
			},
		}
		newReport := mobilepkg.Report{
			Permissions: []mobilepkg.Permission{
				{RawName: "android.permission.CAMERA", Source: "manifest"},
				{RawName: "android.permission.INTERNET", Source: "manifest"},
			},
		}

		diff := mobilepkg.DiffReports(oldReport, newReport)
		if len(diff.AddedPermissions) != 1 {
			t.Fatalf("AddedPermissions = %d, want 1", len(diff.AddedPermissions))
		}
		if diff.AddedPermissions[0].RawName != "android.permission.INTERNET" {
			t.Errorf("AddedPermissions[0].RawName = %q, want %q",
				diff.AddedPermissions[0].RawName, "android.permission.INTERNET")
		}
	})

	t.Run("detects removed permissions", func(t *testing.T) {
		t.Parallel()
		oldReport := mobilepkg.Report{
			Permissions: []mobilepkg.Permission{
				{RawName: "android.permission.CAMERA", Source: "manifest"},
				{RawName: "android.permission.INTERNET", Source: "manifest"},
			},
		}
		newReport := mobilepkg.Report{
			Permissions: []mobilepkg.Permission{
				{RawName: "android.permission.CAMERA", Source: "manifest"},
			},
		}

		diff := mobilepkg.DiffReports(oldReport, newReport)
		if len(diff.RemovedPermissions) != 1 {
			t.Fatalf("RemovedPermissions = %d, want 1", len(diff.RemovedPermissions))
		}
		if diff.RemovedPermissions[0].RawName != "android.permission.INTERNET" {
			t.Errorf("RemovedPermissions[0].RawName = %q, want %q",
				diff.RemovedPermissions[0].RawName, "android.permission.INTERNET")
		}
	})

	t.Run("detects entry point change", func(t *testing.T) {
		t.Parallel()
		oldReport := mobilepkg.Report{
			Entry: mobilepkg.EntryPoint{Kind: "activity", Name: "com.app.OldMain"},
		}
		newReport := mobilepkg.Report{
			Entry: mobilepkg.EntryPoint{Kind: "activity", Name: "com.app.NewMain"},
		}

		diff := mobilepkg.DiffReports(oldReport, newReport)
		if !diff.EntryChanged {
			t.Error("EntryChanged should be true")
		}
	})

	t.Run("tracks platform of both reports", func(t *testing.T) {
		t.Parallel()
		oldReport := mobilepkg.Report{Platform: mobilepkg.PlatformAndroid}
		newReport := mobilepkg.Report{Platform: mobilepkg.PlatformIOS}

		diff := mobilepkg.DiffReports(oldReport, newReport)
		if diff.OldPlatform != mobilepkg.PlatformAndroid {
			t.Errorf("OldPlatform = %q, want %q", diff.OldPlatform, mobilepkg.PlatformAndroid)
		}
		if diff.NewPlatform != mobilepkg.PlatformIOS {
			t.Errorf("NewPlatform = %q, want %q", diff.NewPlatform, mobilepkg.PlatformIOS)
		}
	})
}
