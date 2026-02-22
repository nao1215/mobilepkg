package mobilepkg_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nao1215/mobilepkg"
)

func TestInspectError_Error(t *testing.T) {
	t.Parallel()

	t.Run("formats with underlying error", func(t *testing.T) {
		t.Parallel()
		ie := &mobilepkg.InspectError{
			Code:    "manifest.missing",
			Message: "primary manifest not found",
			Err:     mobilepkg.ErrManifestMissing,
		}
		got := ie.Error()
		want := "mobilepkg [manifest.missing]: mobilepkg: primary manifest not found"
		if got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	})

	t.Run("formats without underlying error", func(t *testing.T) {
		t.Parallel()
		ie := &mobilepkg.InspectError{
			Code:    "format.unsupported",
			Message: "unrecognized package format",
		}
		got := ie.Error()
		want := "mobilepkg [format.unsupported]: unrecognized package format"
		if got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	})
}

func TestInspectError_Unwrap(t *testing.T) {
	t.Parallel()

	t.Run("unwraps to underlying error", func(t *testing.T) {
		t.Parallel()
		ie := &mobilepkg.InspectError{
			Code:    "manifest.missing",
			Message: "primary manifest not found",
			Err:     mobilepkg.ErrManifestMissing,
		}
		if ie.Unwrap() != mobilepkg.ErrManifestMissing {
			t.Errorf("Unwrap() = %v, want ErrManifestMissing", ie.Unwrap())
		}
	})

	t.Run("unwraps to nil when no underlying error", func(t *testing.T) {
		t.Parallel()
		ie := &mobilepkg.InspectError{
			Code:    "unknown",
			Message: "something failed",
		}
		if ie.Unwrap() != nil {
			t.Errorf("Unwrap() = %v, want nil", ie.Unwrap())
		}
	})
}

func TestInspectError_ErrorsIs(t *testing.T) {
	t.Parallel()

	t.Run("errors.Is matches ErrUnsupportedFormat through InspectError", func(t *testing.T) {
		t.Parallel()
		ie := &mobilepkg.InspectError{
			Code:    "format.unsupported",
			Message: "file is not a valid ZIP archive",
			Err:     mobilepkg.ErrUnsupportedFormat,
		}
		if !errors.Is(ie, mobilepkg.ErrUnsupportedFormat) {
			t.Error("errors.Is should match ErrUnsupportedFormat")
		}
	})

	t.Run("errors.Is matches ErrManifestMissing through InspectError", func(t *testing.T) {
		t.Parallel()
		ie := &mobilepkg.InspectError{
			Code:    "manifest.missing",
			Message: "primary manifest not found",
			Err:     mobilepkg.ErrManifestMissing,
		}
		if !errors.Is(ie, mobilepkg.ErrManifestMissing) {
			t.Error("errors.Is should match ErrManifestMissing")
		}
	})

	t.Run("errors.Is matches ErrManifestCorrupt through InspectError", func(t *testing.T) {
		t.Parallel()
		ie := &mobilepkg.InspectError{
			Code:    "manifest.corrupt",
			Message: "manifest could not be parsed",
			Err:     mobilepkg.ErrManifestCorrupt,
		}
		if !errors.Is(ie, mobilepkg.ErrManifestCorrupt) {
			t.Error("errors.Is should match ErrManifestCorrupt")
		}
	})

	t.Run("errors.Is matches ErrArchiveCorrupt through InspectError", func(t *testing.T) {
		t.Parallel()
		ie := &mobilepkg.InspectError{
			Code:    "archive.corrupt",
			Message: "archive is damaged",
			Err:     mobilepkg.ErrArchiveCorrupt,
		}
		if !errors.Is(ie, mobilepkg.ErrArchiveCorrupt) {
			t.Error("errors.Is should match ErrArchiveCorrupt")
		}
	})

	t.Run("errors.Is does not match unrelated sentinel", func(t *testing.T) {
		t.Parallel()
		ie := &mobilepkg.InspectError{
			Code:    "format.unsupported",
			Message: "file is not valid",
			Err:     mobilepkg.ErrUnsupportedFormat,
		}
		if errors.Is(ie, mobilepkg.ErrManifestMissing) {
			t.Error("errors.Is should not match ErrManifestMissing for format error")
		}
	})
}

func TestInspectError_ErrorsAs(t *testing.T) {
	t.Parallel()

	t.Run("errors.As extracts InspectError", func(t *testing.T) {
		t.Parallel()
		var err error = &mobilepkg.InspectError{
			Code:    "manifest.missing",
			Message: "primary manifest not found",
			Err:     mobilepkg.ErrManifestMissing,
		}

		var ie *mobilepkg.InspectError
		if !errors.As(err, &ie) {
			t.Fatal("errors.As should extract InspectError")
		}
		if ie.Code != "manifest.missing" {
			t.Errorf("Code = %q, want %q", ie.Code, "manifest.missing")
		}
		if ie.Message != "primary manifest not found" {
			t.Errorf("Message = %q, want %q", ie.Message, "primary manifest not found")
		}
	})

	t.Run("errors.As does not match for plain error", func(t *testing.T) {
		t.Parallel()
		err := errors.New("plain error")
		var ie *mobilepkg.InspectError
		if errors.As(err, &ie) {
			t.Error("errors.As should not match InspectError for plain error")
		}
	})
}

func TestInspectFile_ReturnsInspectError(t *testing.T) {
	t.Parallel()

	t.Run("non-zip file returns InspectError with format.unsupported", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "notzip.apk")
		if err := os.WriteFile(path, []byte("this is not a zip"), 0o644); err != nil {
			t.Fatal(err)
		}

		_, err := mobilepkg.InspectFile(context.Background(), path, mobilepkg.InspectOptions{})
		if err == nil {
			t.Fatal("InspectFile should return error for non-zip file")
		}

		var ie *mobilepkg.InspectError
		if !errors.As(err, &ie) {
			t.Fatalf("error should be InspectError, got %T: %v", err, err)
		}
		if ie.Code != "format.unsupported" {
			t.Errorf("Code = %q, want %q", ie.Code, "format.unsupported")
		}
		if !errors.Is(err, mobilepkg.ErrUnsupportedFormat) {
			t.Error("error should match ErrUnsupportedFormat via errors.Is")
		}
	})

	t.Run("empty zip returns InspectError with format.unsupported", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := createEmptyZip(t, dir)

		_, err := mobilepkg.InspectFile(context.Background(), path, mobilepkg.InspectOptions{})
		if err == nil {
			t.Fatal("InspectFile should return error for empty zip")
		}

		var ie *mobilepkg.InspectError
		if !errors.As(err, &ie) {
			t.Fatalf("error should be InspectError, got %T: %v", err, err)
		}
		if ie.Code != "format.unsupported" {
			t.Errorf("Code = %q, want %q", ie.Code, "format.unsupported")
		}
	})

	t.Run("cancelled context returns context error", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := mobilepkg.InspectFile(ctx, "any.apk", mobilepkg.InspectOptions{})
		if err == nil {
			t.Fatal("InspectFile should return error for cancelled context")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error should match context.Canceled, got: %v", err)
		}
	})
}

func TestInspectFile_ErrorsIs_ManifestCorrupt(t *testing.T) {
	t.Parallel()

	// A fake APK with a corrupt (plain-text) AndroidManifest.xml triggers
	// a manifest parse error from the internal android adapter. After
	// wrapInspectError, the returned error must match ErrManifestCorrupt.
	dir := t.TempDir()
	apkPath := createTestAPK(t, dir) // text XML → binary parser fails

	_, err := mobilepkg.InspectFile(context.Background(), apkPath, mobilepkg.InspectOptions{
		Sections: mobilepkg.SectionIdentity,
	})
	if err == nil {
		t.Fatal("InspectFile should return error for corrupt manifest")
	}

	if !errors.Is(err, mobilepkg.ErrManifestCorrupt) {
		t.Errorf("errors.Is(err, ErrManifestCorrupt) = false; err = %v", err)
	}

	var ie *mobilepkg.InspectError
	if !errors.As(err, &ie) {
		t.Fatalf("error should be InspectError, got %T: %v", err, err)
	}
	if ie.Code != "manifest.corrupt" {
		t.Errorf("Code = %q, want %q", ie.Code, "manifest.corrupt")
	}
}

func TestSentinelErrors_AreDistinct(t *testing.T) {
	t.Parallel()

	sentinels := []struct {
		name string
		err  error
	}{
		{"ErrUnsupportedFormat", mobilepkg.ErrUnsupportedFormat},
		{"ErrManifestMissing", mobilepkg.ErrManifestMissing},
		{"ErrManifestCorrupt", mobilepkg.ErrManifestCorrupt},
		{"ErrArchiveCorrupt", mobilepkg.ErrArchiveCorrupt},
	}

	for i, a := range sentinels {
		for j, b := range sentinels {
			if i == j {
				continue
			}
			if errors.Is(a.err, b.err) {
				t.Errorf("%s should not match %s via errors.Is", a.name, b.name)
			}
		}
	}
}

func TestDiagnostic_DetailField(t *testing.T) {
	t.Parallel()

	t.Run("Detail can hold metadata", func(t *testing.T) {
		t.Parallel()
		d := mobilepkg.Diagnostic{
			Code:     "icon.not_found",
			Severity: mobilepkg.SeverityWarn,
			Message:  "icon not found",
			Detail:   map[string]string{"path": "res/icon.png"},
		}
		if d.Detail["path"] != "res/icon.png" {
			t.Errorf("Detail[path] = %q, want %q", d.Detail["path"], "res/icon.png")
		}
	})

	t.Run("Detail can be nil", func(t *testing.T) {
		t.Parallel()
		d := mobilepkg.Diagnostic{
			Code:     "icon.not_found",
			Severity: mobilepkg.SeverityWarn,
			Message:  "icon not found",
		}
		if d.Detail != nil {
			t.Errorf("Detail should be nil, got %v", d.Detail)
		}
	})
}

func TestSeverity_Values(t *testing.T) {
	t.Parallel()

	if mobilepkg.SeverityInfo != "info" {
		t.Errorf("SeverityInfo = %q, want %q", mobilepkg.SeverityInfo, "info")
	}
	if mobilepkg.SeverityWarn != "warn" {
		t.Errorf("SeverityWarn = %q, want %q", mobilepkg.SeverityWarn, "warn")
	}
	if mobilepkg.SeverityError != "error" {
		t.Errorf("SeverityError = %q, want %q", mobilepkg.SeverityError, "error")
	}
}
