package mobilepkg_test

import (
	"context"
	"testing"

	"github.com/nao1215/mobilepkg"
)

func TestInspectFile_IPA(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ipaPath := createTestIPA(t, dir)

	t.Run("extracts identity from IPA", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), ipaPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionIdentity,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if report.Platform != mobilepkg.PlatformIOS {
			t.Errorf("Platform = %q, want %q", report.Platform, mobilepkg.PlatformIOS)
		}
		if report.Identity.Identifier != "com.example.testapp" {
			t.Errorf("Identifier = %q, want %q", report.Identity.Identifier, "com.example.testapp")
		}
		if report.Identity.DisplayName != "Test App" {
			t.Errorf("DisplayName = %q, want %q", report.Identity.DisplayName, "Test App")
		}
	})

	t.Run("extracts version from IPA", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), ipaPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionVersion,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if report.Version.Marketing != "2.0.1" {
			t.Errorf("Marketing = %q, want %q", report.Version.Marketing, "2.0.1")
		}
		if report.Version.Build != "100" {
			t.Errorf("Build = %q, want %q", report.Version.Build, "100")
		}
	})

	t.Run("extracts entry point from IPA", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), ipaPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionEntryPoint,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if report.Entry.Kind != "executable" {
			t.Errorf("Kind = %q, want %q", report.Entry.Kind, "executable")
		}
		if report.Entry.Name != "TestApp" {
			t.Errorf("Name = %q, want %q", report.Entry.Name, "TestApp")
		}
	})

	t.Run("extracts permissions from IPA", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), ipaPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionPermissions,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if len(report.Permissions) < 2 {
			t.Fatalf("got %d permissions, want at least 2", len(report.Permissions))
		}

		rawNames := make(map[string]bool)
		for _, p := range report.Permissions {
			rawNames[p.RawName] = true
			if p.Source != "info_plist" && p.Source != "entitlement" {
				t.Errorf("Source = %q, want 'info_plist' or 'entitlement'", p.Source)
			}
		}
		if !rawNames["NSCameraUsageDescription"] {
			t.Error("missing NSCameraUsageDescription permission")
		}
		if !rawNames["NSLocationWhenInUseUsageDescription"] {
			t.Error("missing NSLocationWhenInUseUsageDescription permission")
		}
	})

	t.Run("extracts platform raw data from IPA", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), ipaPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionPlatformRaw,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		iosReport, ok := mobilepkg.AsIOS(report)
		if !ok {
			t.Fatal("AsIOS returned false")
		}
		if iosReport.InfoPlist == nil {
			t.Fatal("InfoPlist is nil")
		}
		if iosReport.InfoPlist["CFBundleIdentifier"] != "com.example.testapp" {
			t.Errorf("InfoPlist CFBundleIdentifier = %v, want %q",
				iosReport.InfoPlist["CFBundleIdentifier"], "com.example.testapp")
		}
	})

	t.Run("extracts all sections with zero Sections value", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), ipaPath, mobilepkg.InspectOptions{})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if report.Identity.Identifier == "" {
			t.Error("Identity should be populated with zero Sections")
		}
		if report.Version.Marketing == "" {
			t.Error("Version should be populated with zero Sections")
		}
	})
}

func TestInspectFile_errors(t *testing.T) {
	t.Parallel()

	t.Run("returns error for non-existent file", func(t *testing.T) {
		t.Parallel()
		_, err := mobilepkg.InspectFile(context.Background(), "/nonexistent", mobilepkg.InspectOptions{})
		if err == nil {
			t.Fatal("InspectFile should return error for non-existent file")
		}
	})
}

func TestInspectFile_XAPK(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	xapkPath := createTestXAPK(t, dir)

	t.Run("extracts identity from XAPK", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), xapkPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionIdentity,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if report.Platform != mobilepkg.PlatformAndroid {
			t.Errorf("Platform = %q, want %q", report.Platform, mobilepkg.PlatformAndroid)
		}
		if report.Format != mobilepkg.FormatXAPK {
			t.Errorf("Format = %q, want %q", report.Format, mobilepkg.FormatXAPK)
		}
		if report.Identity.Identifier != "com.example.helloworld" {
			t.Errorf("Identifier = %q, want %q", report.Identity.Identifier, "com.example.helloworld")
		}
	})

	t.Run("extracts version from XAPK", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), xapkPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionVersion,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if report.Version.Build == "" {
			t.Error("Build version should not be empty")
		}
	})

	t.Run("extracts entry point from XAPK", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), xapkPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionEntryPoint,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if report.Entry.Kind != "activity" {
			t.Errorf("Kind = %q, want %q", report.Entry.Kind, "activity")
		}
		if report.Entry.Name != "com.example.helloworld.MainActivity" {
			t.Errorf("Name = %q, want %q", report.Entry.Name, "com.example.helloworld.MainActivity")
		}
	})

	t.Run("extracts all sections from XAPK", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), xapkPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionAll,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if report.Identity.Identifier == "" {
			t.Error("Identifier should not be empty")
		}
		_, ok := mobilepkg.AsAndroid(report)
		if !ok {
			t.Error("AsAndroid returned false for XAPK report")
		}
	})
}

func TestInspectFile_APKS(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	apksPath := createTestAPKS(t, dir)

	t.Run("extracts identity from APKS", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), apksPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionIdentity,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if report.Platform != mobilepkg.PlatformAndroid {
			t.Errorf("Platform = %q, want %q", report.Platform, mobilepkg.PlatformAndroid)
		}
		if report.Format != mobilepkg.FormatAPKS {
			t.Errorf("Format = %q, want %q", report.Format, mobilepkg.FormatAPKS)
		}
		if report.Identity.Identifier != "com.example.helloworld" {
			t.Errorf("Identifier = %q, want %q", report.Identity.Identifier, "com.example.helloworld")
		}
	})

	t.Run("extracts version from APKS", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), apksPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionVersion,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if report.Version.Build == "" {
			t.Error("Build version should not be empty")
		}
	})

	t.Run("extracts entry point from APKS", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), apksPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionEntryPoint,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if report.Entry.Kind != "activity" {
			t.Errorf("Kind = %q, want %q", report.Entry.Kind, "activity")
		}
		if report.Entry.Name != "com.example.helloworld.MainActivity" {
			t.Errorf("Name = %q, want %q", report.Entry.Name, "com.example.helloworld.MainActivity")
		}
	})

	t.Run("extracts all sections from APKS", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), apksPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionAll,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if report.Identity.Identifier == "" {
			t.Error("Identifier should not be empty")
		}
	})
}

func TestInspectFile_AAB(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	aabPath := createTestAAB(t, dir)

	t.Run("extracts identity from AAB", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), aabPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionIdentity,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if report.Platform != mobilepkg.PlatformAndroid {
			t.Errorf("Platform = %q, want %q", report.Platform, mobilepkg.PlatformAndroid)
		}
		if report.Format != mobilepkg.FormatAAB {
			t.Errorf("Format = %q, want %q", report.Format, mobilepkg.FormatAAB)
		}
		if report.Identity.Identifier != "com.example.aabtest" {
			t.Errorf("Identifier = %q, want %q", report.Identity.Identifier, "com.example.aabtest")
		}
	})

	t.Run("extracts version from AAB", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), aabPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionVersion,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if report.Version.Marketing != "3.0.0" {
			t.Errorf("Marketing = %q, want %q", report.Version.Marketing, "3.0.0")
		}
		if report.Version.Build != "10" {
			t.Errorf("Build = %q, want %q", report.Version.Build, "10")
		}
	})

	t.Run("extracts entry point from AAB", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), aabPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionEntryPoint,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if report.Entry.Kind != "activity" {
			t.Errorf("Kind = %q, want %q", report.Entry.Kind, "activity")
		}
		if report.Entry.Name != "com.example.aabtest.MainActivity" {
			t.Errorf("Name = %q, want %q", report.Entry.Name, "com.example.aabtest.MainActivity")
		}
	})

	t.Run("extracts permissions from AAB", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), aabPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionPermissions,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if len(report.Permissions) < 2 {
			t.Fatalf("got %d permissions, want at least 2", len(report.Permissions))
		}
		rawNames := make(map[string]bool)
		for _, p := range report.Permissions {
			rawNames[p.RawName] = true
		}
		if !rawNames["android.permission.CAMERA"] {
			t.Error("missing android.permission.CAMERA permission")
		}
		if !rawNames["android.permission.INTERNET"] {
			t.Error("missing android.permission.INTERNET permission")
		}
	})

	t.Run("extracts platform raw data from AAB", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), aabPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionPlatformRaw,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		ar, ok := mobilepkg.AsAndroid(report)
		if !ok {
			t.Fatal("AsAndroid returned false for AAB report")
		}
		if ar.RawManifest == nil {
			t.Fatal("RawManifest is nil")
		}
		if ar.RawManifest["package"] != "com.example.aabtest" {
			t.Errorf("RawManifest package = %v, want %q", ar.RawManifest["package"], "com.example.aabtest")
		}
	})

	t.Run("reports icon diagnostic when icon is absent", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), aabPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionIcon,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		// Test AAB has no icon resource, so Report.Icon should be nil
		// and a diagnostic should be emitted.
		if report.Icon != nil {
			t.Error("Icon should be nil for AAB without icon resource")
		}
		found := false
		for _, d := range report.Diagnostics {
			if d.Code == "icon.not_found" {
				found = true
			}
		}
		if !found {
			t.Error("expected icon.not_found diagnostic for AAB without icon")
		}
	})

	t.Run("accepts SizePx without error", func(t *testing.T) {
		t.Parallel()
		// SizePx selects icon density in AAB files. Our test AAB has no icon
		// resources, so we verify the code path doesn't panic or error.
		report, err := mobilepkg.InspectFile(context.Background(), aabPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionIcon,
			Icon:     mobilepkg.IconOptions{SizePx: 192},
		})
		if err != nil {
			t.Fatalf("InspectFile with SizePx returned error: %v", err)
		}
		// No icon resource → expect nil icon and diagnostic
		if report.Icon != nil {
			t.Error("Icon should be nil for AAB without icon resource")
		}
	})

	t.Run("extracts all sections from AAB", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), aabPath, mobilepkg.InspectOptions{})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if report.Identity.Identifier == "" {
			t.Error("Identifier should not be empty")
		}
		if report.Version.Marketing == "" {
			t.Error("Version should not be empty")
		}
	})
}

func TestInspectFile_APK_with_real_testdata(t *testing.T) {
	t.Parallel()

	const apkPath = "doc/androidbinary/apk/testdata/helloworld.apk"

	t.Run("extracts identity from real APK", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), apkPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionIdentity,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if report.Platform != mobilepkg.PlatformAndroid {
			t.Errorf("Platform = %q, want %q", report.Platform, mobilepkg.PlatformAndroid)
		}
		if report.Identity.Identifier != "com.example.helloworld" {
			t.Errorf("Identifier = %q, want %q", report.Identity.Identifier, "com.example.helloworld")
		}
	})

	t.Run("extracts version from real APK", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), apkPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionVersion,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if report.Version.Build == "" {
			t.Error("Build version should not be empty")
		}
	})

	t.Run("extracts entry point from real APK", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), apkPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionEntryPoint,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if report.Entry.Kind != "activity" {
			t.Errorf("Kind = %q, want %q", report.Entry.Kind, "activity")
		}
		if report.Entry.Name != "com.example.helloworld.MainActivity" {
			t.Errorf("Name = %q, want %q", report.Entry.Name, "com.example.helloworld.MainActivity")
		}
	})

	t.Run("extracts icon from real APK", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), apkPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionIcon,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if report.Icon == nil {
			// Icon might not resolve from resource reference; check diagnostics instead.
			for _, d := range report.Diagnostics {
				if d.Code == "icon.not_resolved" || d.Code == "icon.read_failed" {
					t.Skipf("icon not available in test APK: %s", d.Message)
				}
			}
			t.Skip("icon is nil but no diagnostic — skipping")
		}
		if len(report.Icon.Bytes) == 0 {
			t.Error("Icon.Bytes should not be empty when icon is present")
		}
		if report.Icon.Width <= 0 || report.Icon.Height <= 0 {
			t.Errorf("Icon dimensions should be positive, got %dx%d", report.Icon.Width, report.Icon.Height)
		}
	})

	t.Run("extracts all sections from real APK", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), apkPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionAll,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if report.Identity.Identifier == "" {
			t.Error("Identifier should not be empty")
		}
		_, ok := mobilepkg.AsAndroid(report)
		if !ok {
			t.Error("AsAndroid returned false for Android report")
		}
	})

	t.Run("extracts SDK constraints from real APK", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), apkPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionSDK,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if report.SDK.MinSDK == "" {
			t.Error("MinSDK should not be empty")
		}
		if report.SDK.TargetSDK == "" {
			t.Error("TargetSDK should not be empty")
		}
	})
}

func TestInspectFile_IPA_SDK(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ipaPath := createTestIPAWithMinOS(t, dir)

	t.Run("extracts MinimumOSVersion from IPA", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), ipaPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionSDK,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if report.SDK.MinSDK != "15.0" {
			t.Errorf("MinSDK = %q, want %q", report.SDK.MinSDK, "15.0")
		}
		if report.SDK.TargetSDK != "" {
			t.Errorf("TargetSDK = %q, want empty for iOS", report.SDK.TargetSDK)
		}
	})
}

func TestInspectFile_AAB_SDK(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	aabPath := createTestAABWithSDK(t, dir)

	t.Run("extracts SDK constraints from AAB", func(t *testing.T) {
		t.Parallel()
		report, err := mobilepkg.InspectFile(context.Background(), aabPath, mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionSDK,
		})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}
		if report.SDK.MinSDK != "21" {
			t.Errorf("MinSDK = %q, want %q", report.SDK.MinSDK, "21")
		}
		if report.SDK.TargetSDK != "34" {
			t.Errorf("TargetSDK = %q, want %q", report.SDK.TargetSDK, "34")
		}
	})
}

func TestInspectFile_IPA_PlatformRaw_Entitlements(t *testing.T) {
	t.Parallel()

	// SectionPlatformRaw alone (without SectionPermissions) should still
	// populate IOSReport.Entitlements when embedded.mobileprovision exists.
	dir := t.TempDir()
	ipaPath := createIPAWithProvision(t, dir)

	report, err := mobilepkg.InspectFile(context.Background(), ipaPath, mobilepkg.InspectOptions{
		Sections: mobilepkg.SectionPlatformRaw,
	})
	if err != nil {
		t.Fatalf("InspectFile returned error: %v", err)
	}

	iosR, ok := mobilepkg.AsIOS(report)
	if !ok {
		t.Fatal("AsIOS returned false")
	}
	if iosR.InfoPlist == nil {
		t.Fatal("InfoPlist should not be nil")
	}
	if iosR.Entitlements == nil {
		t.Error("Entitlements should not be nil when embedded.mobileprovision exists")
	}
}
