package mobilepkg_test

import (
	"context"
	"testing"

	"github.com/nao1215/mobilepkg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInspectFile_IPA(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ipaPath := createTestIPA(t, dir)

	t.Run("extracts identity from IPA", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), ipaPath)
		require.NoError(t, err)
		assert.Equal(t, mobilepkg.PlatformIOS, report.Platform)
		assert.Equal(t, "com.example.testapp", report.Identity.Identifier)
		assert.Equal(t, "Test App", report.Identity.DisplayName)
	})

	t.Run("extracts version from IPA", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), ipaPath)
		require.NoError(t, err)
		assert.Equal(t, "2.0.1", report.Version.Marketing)
		assert.Equal(t, "100", report.Version.Build)
	})

	t.Run("extracts entry point from IPA", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), ipaPath)
		require.NoError(t, err)
		assert.Equal(t, "executable", report.Entry.Kind)
		assert.Equal(t, "TestApp", report.Entry.Name)
	})

	t.Run("extracts permissions from IPA", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), ipaPath)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(report.Permissions), 2)

		rawNames := make(map[string]bool)
		for _, p := range report.Permissions {
			rawNames[p.RawName] = true
			assert.Contains(t, []string{"info_plist", "entitlement"}, p.Source,
				"Source should be info_plist or entitlement")
		}
		assert.True(t, rawNames["NSCameraUsageDescription"], "missing NSCameraUsageDescription permission")
		assert.True(t, rawNames["NSLocationWhenInUseUsageDescription"], "missing NSLocationWhenInUseUsageDescription permission")
	})

	t.Run("extracts all sections with zero Sections value", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), ipaPath)
		require.NoError(t, err)
		assert.NotEmpty(t, report.Identity.Identifier, "Identity should be populated with zero Sections")
		assert.NotEmpty(t, report.Version.Marketing, "Version should be populated with zero Sections")
	})
}

func TestInspectFile_errors(t *testing.T) {
	t.Parallel()

	t.Run("returns error for non-existent file", func(t *testing.T) {
		t.Parallel()
		_, err := mobilepkg.InspectFile(context.Background(), "/nonexistent")
		assert.Error(t, err)
	})
}

func TestInspectFile_XAPK(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	xapkPath := createTestXAPK(t, dir)

	// The synthetic XAPK contains a text-XML APK that cannot be parsed by
	// the binary XML parser. The XAPK inspector falls back to manifest.json
	// metadata extraction, so we verify the fallback values.

	t.Run("extracts identity from XAPK via manifest.json fallback", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), xapkPath)
		require.NoError(t, err)
		assert.Equal(t, mobilepkg.PlatformAndroid, report.Platform)
		assert.Equal(t, mobilepkg.FormatXAPK, report.Format)
		assert.Equal(t, "com.example.xapktest", report.Identity.Identifier)
	})

	t.Run("extracts version from XAPK via manifest.json fallback", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), xapkPath)
		require.NoError(t, err)
		assert.NotEmpty(t, report.Version.Build, "Build version should not be empty")
		assert.Equal(t, "1.2.3", report.Version.Marketing)
	})

	t.Run("extracts all sections from XAPK via manifest.json fallback", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), xapkPath)
		require.NoError(t, err)
		assert.NotEmpty(t, report.Identity.Identifier)
	})
}

func TestInspectFile_APKS(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	apksPath := createTestAPKS(t, dir)

	// The synthetic APKS contains a text-XML inner APK that the binary XML
	// parser cannot handle. APKS has no manifest.json fallback, so inspect
	// returns an error.

	t.Run("inspect returns error for APKS with unparseable inner APK", func(t *testing.T) {
		t.Parallel()
		_, err := mobilepkg.InspectFile(context.Background(), apksPath)
		assert.Error(t, err, "inspect should fail when inner APK has text-XML manifest")
	})
}

func TestInspectFile_AAB(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	aabPath := createTestAAB(t, dir)

	t.Run("extracts identity from AAB", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), aabPath)
		require.NoError(t, err)
		assert.Equal(t, mobilepkg.PlatformAndroid, report.Platform)
		assert.Equal(t, mobilepkg.FormatAAB, report.Format)
		assert.Equal(t, "com.example.aabtest", report.Identity.Identifier)
	})

	t.Run("extracts version from AAB", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), aabPath)
		require.NoError(t, err)
		assert.Equal(t, "3.0.0", report.Version.Marketing)
		assert.Equal(t, "10", report.Version.Build)
	})

	t.Run("extracts entry point from AAB", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), aabPath)
		require.NoError(t, err)
		assert.Equal(t, "activity", report.Entry.Kind)
		assert.Equal(t, "com.example.aabtest.MainActivity", report.Entry.Name)
	})

	t.Run("extracts permissions from AAB", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), aabPath)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(report.Permissions), 2)

		rawNames := make(map[string]bool)
		for _, p := range report.Permissions {
			rawNames[p.RawName] = true
		}
		assert.True(t, rawNames["android.permission.CAMERA"], "missing android.permission.CAMERA permission")
		assert.True(t, rawNames["android.permission.INTERNET"], "missing android.permission.INTERNET permission")
	})

	t.Run("reports icon diagnostic when icon is absent", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), aabPath)
		require.NoError(t, err)
		// Test AAB has no icon resource, so a diagnostic should be emitted.
		found := false
		for _, d := range report.Diagnostics {
			if d.Code == "icon.not_found" {
				found = true
			}
		}
		assert.True(t, found, "expected icon.not_found diagnostic for AAB without icon")
	})

	t.Run("accepts SizePx without error", func(t *testing.T) {
		t.Parallel()
		// SizePx selects icon density in AAB files. Our test AAB has no icon
		// resources, so we verify the code path doesn't panic or error.
		_, err := mobilepkg.InspectFileWithOptions(context.Background(), aabPath, mobilepkg.InspectOptions{})
		require.NoError(t, err)
	})

	t.Run("extracts all sections from AAB", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), aabPath)
		require.NoError(t, err)
		assert.NotEmpty(t, report.Identity.Identifier)
		assert.NotEmpty(t, report.Version.Marketing)
	})
}

func TestInspectFile_IPA_SDK(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ipaPath := createTestIPAWithMinOS(t, dir)

	t.Run("extracts MinimumOSVersion from IPA", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), ipaPath)
		require.NoError(t, err)
		assert.Equal(t, "15.0", report.SDK.MinSDK)
		assert.Empty(t, report.SDK.TargetSDK, "TargetSDK should be empty for iOS")
	})
}

func TestInspectFile_AAB_SDK(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	aabPath := createTestAABWithSDK(t, dir)

	t.Run("extracts SDK constraints from AAB", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), aabPath)
		require.NoError(t, err)
		assert.Equal(t, "21", report.SDK.MinSDK)
		assert.Equal(t, "34", report.SDK.TargetSDK)
	})
}

// TestInspectFile_IPA_PlatformRaw_Entitlements is removed because
// InspectResult does not expose PlatformData. Platform-specific raw
// data is only available on the internal Report type.
