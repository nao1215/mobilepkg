package mobilepkg_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nao1215/mobilepkg"
)

func TestProbeFile(t *testing.T) {
	t.Parallel()

	t.Run("detects APK by AndroidManifest.xml presence", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		apkPath := createTestAPK(t, dir)

		result, err := mobilepkg.ProbeFile(apkPath)
		if err != nil {
			t.Fatalf("ProbeFile returned error: %v", err)
		}
		if result.Platform != mobilepkg.PlatformAndroid {
			t.Errorf("Platform = %q, want %q", result.Platform, mobilepkg.PlatformAndroid)
		}
		if result.Container != "zip" {
			t.Errorf("Container = %q, want %q", result.Container, "zip")
		}
		found := false
		for _, h := range result.Hints {
			if h == "has AndroidManifest.xml" {
				found = true
			}
		}
		if !found {
			t.Errorf("Hints = %v, want to contain %q", result.Hints, "has AndroidManifest.xml")
		}
	})

	t.Run("detects IPA by Info.plist presence", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		ipaPath := createTestIPA(t, dir)

		result, err := mobilepkg.ProbeFile(ipaPath)
		if err != nil {
			t.Fatalf("ProbeFile returned error: %v", err)
		}
		if result.Platform != mobilepkg.PlatformIOS {
			t.Errorf("Platform = %q, want %q", result.Platform, mobilepkg.PlatformIOS)
		}
		if result.Container != "zip" {
			t.Errorf("Container = %q, want %q", result.Container, "zip")
		}
		found := false
		for _, h := range result.Hints {
			if h == "has Info.plist" {
				found = true
			}
		}
		if !found {
			t.Errorf("Hints = %v, want to contain %q", result.Hints, "has Info.plist")
		}
	})

	t.Run("returns error for non-existent file", func(t *testing.T) {
		t.Parallel()
		_, err := mobilepkg.ProbeFile("/nonexistent/path/app.apk")
		if err == nil {
			t.Fatal("ProbeFile should return error for non-existent file")
		}
	})

	t.Run("returns ErrUnsupportedFormat for non-zip file", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "notzip.apk")
		if err := os.WriteFile(path, []byte("this is not a zip"), 0o644); err != nil {
			t.Fatal(err)
		}

		_, err := mobilepkg.ProbeFile(path)
		if err == nil {
			t.Fatal("ProbeFile should return error for non-zip file")
		}
	})

	t.Run("detects XAPK by manifest.json and inner APK", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		xapkPath := createTestXAPK(t, dir)

		result, err := mobilepkg.ProbeFile(xapkPath)
		if err != nil {
			t.Fatalf("ProbeFile returned error: %v", err)
		}
		if result.Platform != mobilepkg.PlatformAndroid {
			t.Errorf("Platform = %q, want %q", result.Platform, mobilepkg.PlatformAndroid)
		}
		if result.Format != mobilepkg.FormatXAPK {
			t.Errorf("Format = %q, want %q", result.Format, mobilepkg.FormatXAPK)
		}
		if result.Container != "zip" {
			t.Errorf("Container = %q, want %q", result.Container, "zip")
		}
	})

	t.Run("detects APKS by toc.pb and splits/*.apk", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		apksPath := createTestAPKS(t, dir)

		result, err := mobilepkg.ProbeFile(apksPath)
		if err != nil {
			t.Fatalf("ProbeFile returned error: %v", err)
		}
		if result.Platform != mobilepkg.PlatformAndroid {
			t.Errorf("Platform = %q, want %q", result.Platform, mobilepkg.PlatformAndroid)
		}
		if result.Format != mobilepkg.FormatAPKS {
			t.Errorf("Format = %q, want %q", result.Format, mobilepkg.FormatAPKS)
		}
	})

	t.Run("detects AAB by base/manifest and BundleConfig.pb", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		aabPath := createTestAAB(t, dir)

		result, err := mobilepkg.ProbeFile(aabPath)
		if err != nil {
			t.Fatalf("ProbeFile returned error: %v", err)
		}
		if result.Platform != mobilepkg.PlatformAndroid {
			t.Errorf("Platform = %q, want %q", result.Platform, mobilepkg.PlatformAndroid)
		}
		if result.Format != mobilepkg.FormatAAB {
			t.Errorf("Format = %q, want %q", result.Format, mobilepkg.FormatAAB)
		}
	})

	t.Run("reports correct Format for APK", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		apkPath := createTestAPK(t, dir)

		result, err := mobilepkg.ProbeFile(apkPath)
		if err != nil {
			t.Fatalf("ProbeFile returned error: %v", err)
		}
		if result.Format != mobilepkg.FormatAPK {
			t.Errorf("Format = %q, want %q", result.Format, mobilepkg.FormatAPK)
		}
	})

	t.Run("reports correct Format for IPA", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		ipaPath := createTestIPA(t, dir)

		result, err := mobilepkg.ProbeFile(ipaPath)
		if err != nil {
			t.Fatalf("ProbeFile returned error: %v", err)
		}
		if result.Format != mobilepkg.FormatIPA {
			t.Errorf("Format = %q, want %q", result.Format, mobilepkg.FormatIPA)
		}
	})
}

func TestProbe_ReaderAt(t *testing.T) {
	t.Parallel()

	t.Run("detects APK from in-memory bytes", func(t *testing.T) {
		t.Parallel()
		data, err := os.ReadFile("doc/androidbinary/apk/testdata/helloworld.apk")
		if err != nil {
			t.Fatal(err)
		}

		result, err := mobilepkg.Probe(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatalf("Probe returned error: %v", err)
		}
		if result.Platform != mobilepkg.PlatformAndroid {
			t.Errorf("Platform = %q, want %q", result.Platform, mobilepkg.PlatformAndroid)
		}
		if result.Format != mobilepkg.FormatAPK {
			t.Errorf("Format = %q, want %q", result.Format, mobilepkg.FormatAPK)
		}
	})

	t.Run("returns error for non-zip data", func(t *testing.T) {
		t.Parallel()
		data := []byte("not a zip file")
		_, err := mobilepkg.Probe(bytes.NewReader(data), int64(len(data)))
		if err == nil {
			t.Fatal("Probe should return error for non-zip data")
		}
	})
}

func TestInspect_ReaderAt(t *testing.T) {
	t.Parallel()

	t.Run("inspects APK from in-memory bytes", func(t *testing.T) {
		t.Parallel()
		data, err := os.ReadFile("doc/androidbinary/apk/testdata/helloworld.apk")
		if err != nil {
			t.Fatal(err)
		}

		report, err := mobilepkg.Inspect(context.Background(),
			bytes.NewReader(data), int64(len(data)),
			mobilepkg.InspectOptions{Sections: mobilepkg.SectionIdentity})
		if err != nil {
			t.Fatalf("Inspect returned error: %v", err)
		}
		if report.Identity.Identifier != "com.example.helloworld" {
			t.Errorf("Identifier = %q, want %q", report.Identity.Identifier, "com.example.helloworld")
		}
	})

	t.Run("Inspect matches InspectFile", func(t *testing.T) {
		t.Parallel()
		const path = "doc/androidbinary/apk/testdata/helloworld.apk"
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}

		fileReport, err := mobilepkg.InspectFile(context.Background(), path,
			mobilepkg.InspectOptions{Sections: mobilepkg.SectionIdentity | mobilepkg.SectionVersion})
		if err != nil {
			t.Fatalf("InspectFile returned error: %v", err)
		}

		memReport, err := mobilepkg.Inspect(context.Background(),
			bytes.NewReader(data), int64(len(data)),
			mobilepkg.InspectOptions{Sections: mobilepkg.SectionIdentity | mobilepkg.SectionVersion})
		if err != nil {
			t.Fatalf("Inspect returned error: %v", err)
		}

		if fileReport.Identity != memReport.Identity {
			t.Errorf("Identity mismatch: file=%+v mem=%+v", fileReport.Identity, memReport.Identity)
		}
		if fileReport.Version != memReport.Version {
			t.Errorf("Version mismatch: file=%+v mem=%+v", fileReport.Version, memReport.Version)
		}
	})
}
