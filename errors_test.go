package mobilepkg_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nao1215/mobilepkg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		assert.Equal(t, "mobilepkg [manifest.missing]: mobilepkg: primary manifest not found", ie.Error())
	})

	t.Run("formats without underlying error", func(t *testing.T) {
		t.Parallel()
		ie := &mobilepkg.InspectError{
			Code:    "format.unsupported",
			Message: "unrecognized package format",
		}
		assert.Equal(t, "mobilepkg [format.unsupported]: unrecognized package format", ie.Error())
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
		assert.ErrorIs(t, ie.Unwrap(), mobilepkg.ErrManifestMissing)
	})

	t.Run("unwraps to nil when no underlying error", func(t *testing.T) {
		t.Parallel()
		ie := &mobilepkg.InspectError{
			Code:    "unknown",
			Message: "something failed",
		}
		assert.Nil(t, ie.Unwrap())
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
		assert.ErrorIs(t, ie, mobilepkg.ErrUnsupportedFormat)
	})

	t.Run("errors.Is matches ErrManifestMissing through InspectError", func(t *testing.T) {
		t.Parallel()
		ie := &mobilepkg.InspectError{
			Code:    "manifest.missing",
			Message: "primary manifest not found",
			Err:     mobilepkg.ErrManifestMissing,
		}
		assert.ErrorIs(t, ie, mobilepkg.ErrManifestMissing)
	})

	t.Run("errors.Is matches ErrManifestCorrupt through InspectError", func(t *testing.T) {
		t.Parallel()
		ie := &mobilepkg.InspectError{
			Code:    "manifest.corrupt",
			Message: "manifest could not be parsed",
			Err:     mobilepkg.ErrManifestCorrupt,
		}
		assert.ErrorIs(t, ie, mobilepkg.ErrManifestCorrupt)
	})

	t.Run("errors.Is matches ErrArchiveCorrupt through InspectError", func(t *testing.T) {
		t.Parallel()
		ie := &mobilepkg.InspectError{
			Code:    "archive.corrupt",
			Message: "archive is damaged",
			Err:     mobilepkg.ErrArchiveCorrupt,
		}
		assert.ErrorIs(t, ie, mobilepkg.ErrArchiveCorrupt)
	})

	t.Run("errors.Is does not match unrelated sentinel", func(t *testing.T) {
		t.Parallel()
		ie := &mobilepkg.InspectError{
			Code:    "format.unsupported",
			Message: "file is not valid",
			Err:     mobilepkg.ErrUnsupportedFormat,
		}
		assert.NotErrorIs(t, ie, mobilepkg.ErrManifestMissing)
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
		require.ErrorAs(t, err, &ie)
		assert.Equal(t, "manifest.missing", ie.Code)
		assert.Equal(t, "primary manifest not found", ie.Message)
	})

	t.Run("errors.As does not match for plain error", func(t *testing.T) {
		t.Parallel()
		err := errors.New("plain error")
		var ie *mobilepkg.InspectError
		assert.False(t, errors.As(err, &ie))
	})
}

func TestInspectFile_ReturnsInspectError(t *testing.T) {
	t.Parallel()

	t.Run("non-zip file returns InspectError with format.unsupported", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "notzip.apk")
		err := os.WriteFile(path, []byte("this is not a zip"), 0o644)
		require.NoError(t, err)

		_, inspErr := mobilepkg.InspectFile(context.Background(), path)
		require.Error(t, inspErr)

		var ie *mobilepkg.InspectError
		require.ErrorAs(t, inspErr, &ie)
		assert.Equal(t, "format.unsupported", ie.Code)
		assert.ErrorIs(t, inspErr, mobilepkg.ErrUnsupportedFormat)
	})

	t.Run("empty zip returns InspectError with format.unsupported", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := createEmptyZip(t, dir)

		_, inspErr := mobilepkg.InspectFile(context.Background(), path)
		require.Error(t, inspErr)

		var ie *mobilepkg.InspectError
		require.ErrorAs(t, inspErr, &ie)
		assert.Equal(t, "format.unsupported", ie.Code)
	})

	t.Run("cancelled context returns context error", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := mobilepkg.InspectFile(ctx, "any.apk")
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})
}

func TestInspectFile_ErrorsIs_ManifestCorrupt(t *testing.T) {
	t.Parallel()

	// A fake APK with a corrupt (plain-text) AndroidManifest.xml triggers
	// a manifest parse error from the internal android adapter. After
	// wrapInspectError, the returned error must match ErrManifestCorrupt.
	dir := t.TempDir()
	apkPath := createTestAPK(t, dir) // text XML -> binary parser fails

	_, err := mobilepkg.InspectFile(context.Background(), apkPath)
	require.Error(t, err)
	assert.ErrorIs(t, err, mobilepkg.ErrManifestCorrupt)

	var ie *mobilepkg.InspectError
	require.ErrorAs(t, err, &ie)
	assert.Equal(t, "manifest.corrupt", ie.Code)
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
			assert.NotErrorIs(t, a.err, b.err, "%s should not match %s via errors.Is", a.name, b.name)
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
		assert.Equal(t, "res/icon.png", d.Detail["path"])
	})

	t.Run("Detail can be nil", func(t *testing.T) {
		t.Parallel()
		d := mobilepkg.Diagnostic{
			Code:     "icon.not_found",
			Severity: mobilepkg.SeverityWarn,
			Message:  "icon not found",
		}
		assert.Nil(t, d.Detail)
	})
}

func TestSeverity_Values(t *testing.T) {
	t.Parallel()

	assert.Equal(t, mobilepkg.Severity("info"), mobilepkg.SeverityInfo)
	assert.Equal(t, mobilepkg.Severity("warn"), mobilepkg.SeverityWarn)
	assert.Equal(t, mobilepkg.Severity("error"), mobilepkg.SeverityError)
}
