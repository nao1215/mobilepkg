package mobilepkg_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nao1215/mobilepkg"
)

const realAPKPath = "doc/androidbinary/apk/testdata/helloworld.apk"

func TestInspectFiles(t *testing.T) {
	t.Parallel()

	t.Run("inspects multiple files preserving input order", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		ipaPath := createTestIPA(t, dir)

		paths := []string{ipaPath, realAPKPath}
		results := mobilepkg.InspectFiles(context.Background(), paths, mobilepkg.BatchOptions{
			InspectOptions: mobilepkg.InspectOptions{Sections: mobilepkg.SectionIdentity},
		})

		if len(results) != 2 {
			t.Fatalf("expected 2 results, got %d", len(results))
		}
		if results[0].Path != ipaPath {
			t.Errorf("results[0].Path = %q, want %q", results[0].Path, ipaPath)
		}
		if results[1].Path != realAPKPath {
			t.Errorf("results[1].Path = %q, want %q", results[1].Path, realAPKPath)
		}
		if results[0].Err != nil {
			t.Errorf("results[0].Err = %v, want nil", results[0].Err)
		}
		if results[1].Err != nil {
			t.Errorf("results[1].Err = %v, want nil", results[1].Err)
		}
		if results[0].Report.Platform != mobilepkg.PlatformIOS {
			t.Errorf("results[0].Platform = %q, want %q", results[0].Report.Platform, mobilepkg.PlatformIOS)
		}
		if results[1].Report.Platform != mobilepkg.PlatformAndroid {
			t.Errorf("results[1].Platform = %q, want %q", results[1].Report.Platform, mobilepkg.PlatformAndroid)
		}
	})

	t.Run("partial failure with bad file", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		badPath := filepath.Join(dir, "bad.apk")
		if err := os.WriteFile(badPath, []byte("not a zip"), 0o644); err != nil {
			t.Fatal(err)
		}

		paths := []string{realAPKPath, badPath}
		results := mobilepkg.InspectFiles(context.Background(), paths, mobilepkg.BatchOptions{})

		if results[0].Err != nil {
			t.Errorf("results[0].Err = %v, want nil", results[0].Err)
		}
		if results[1].Err == nil {
			t.Error("results[1].Err should be non-nil for bad file")
		}
	})

	t.Run("cancelled context skips files", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		paths := []string{"/nonexistent/a.apk", "/nonexistent/b.apk"}
		results := mobilepkg.InspectFiles(ctx, paths, mobilepkg.BatchOptions{})

		if len(results) != 2 {
			t.Fatalf("expected 2 results, got %d", len(results))
		}
		for i, r := range results {
			if r.Err == nil {
				t.Errorf("results[%d].Err should be non-nil for cancelled context", i)
			}
		}
	})

	t.Run("empty input returns empty results", func(t *testing.T) {
		t.Parallel()
		results := mobilepkg.InspectFiles(context.Background(), nil, mobilepkg.BatchOptions{})
		if len(results) != 0 {
			t.Errorf("expected 0 results, got %d", len(results))
		}
	})

	t.Run("respects concurrency setting", func(t *testing.T) {
		t.Parallel()

		results := mobilepkg.InspectFiles(context.Background(), []string{realAPKPath}, mobilepkg.BatchOptions{
			Concurrency: 1,
		})
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		if results[0].Err != nil {
			t.Errorf("Err = %v, want nil", results[0].Err)
		}
	})
}

func TestSortReport_PermissionsAreSorted(t *testing.T) {
	t.Parallel()

	report, err := mobilepkg.InspectFile(context.Background(), realAPKPath, mobilepkg.InspectOptions{
		Sections: mobilepkg.SectionPermissions,
	})
	if err != nil {
		t.Fatalf("InspectFile returned error: %v", err)
	}

	for i := 1; i < len(report.Permissions); i++ {
		if report.Permissions[i-1].RawName > report.Permissions[i].RawName {
			t.Errorf("Permissions not sorted: [%d]=%q > [%d]=%q",
				i-1, report.Permissions[i-1].RawName,
				i, report.Permissions[i].RawName)
		}
	}
}

func TestDiffReports_SortedPermissions(t *testing.T) {
	t.Parallel()

	oldR := mobilepkg.Report{
		Permissions: []mobilepkg.Permission{
			{RawName: "perm.Z"},
			{RawName: "perm.A"},
		},
	}
	newR := mobilepkg.Report{
		Permissions: []mobilepkg.Permission{
			{RawName: "perm.Y"},
			{RawName: "perm.B"},
		},
	}

	diff := mobilepkg.DiffReports(oldR, newR)

	for i := 1; i < len(diff.AddedPermissions); i++ {
		if diff.AddedPermissions[i-1].RawName > diff.AddedPermissions[i].RawName {
			t.Errorf("AddedPermissions not sorted: [%d]=%q > [%d]=%q",
				i-1, diff.AddedPermissions[i-1].RawName,
				i, diff.AddedPermissions[i].RawName)
		}
	}
	for i := 1; i < len(diff.RemovedPermissions); i++ {
		if diff.RemovedPermissions[i-1].RawName > diff.RemovedPermissions[i].RawName {
			t.Errorf("RemovedPermissions not sorted: [%d]=%q > [%d]=%q",
				i-1, diff.RemovedPermissions[i-1].RawName,
				i, diff.RemovedPermissions[i].RawName)
		}
	}

	// Verify expected contents
	if len(diff.AddedPermissions) != 2 {
		t.Fatalf("expected 2 added, got %d", len(diff.AddedPermissions))
	}
	if diff.AddedPermissions[0].RawName != "perm.B" {
		t.Errorf("AddedPermissions[0] = %q, want %q", diff.AddedPermissions[0].RawName, "perm.B")
	}
	if diff.AddedPermissions[1].RawName != "perm.Y" {
		t.Errorf("AddedPermissions[1] = %q, want %q", diff.AddedPermissions[1].RawName, "perm.Y")
	}
	if len(diff.RemovedPermissions) != 2 {
		t.Fatalf("expected 2 removed, got %d", len(diff.RemovedPermissions))
	}
	if diff.RemovedPermissions[0].RawName != "perm.A" {
		t.Errorf("RemovedPermissions[0] = %q, want %q", diff.RemovedPermissions[0].RawName, "perm.A")
	}
	if diff.RemovedPermissions[1].RawName != "perm.Z" {
		t.Errorf("RemovedPermissions[1] = %q, want %q", diff.RemovedPermissions[1].RawName, "perm.Z")
	}
}
