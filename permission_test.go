package mobilepkg_test

import (
	"testing"

	"github.com/nao1215/mobilepkg"
)

func TestAsAndroid(t *testing.T) {
	t.Parallel()

	t.Run("returns typed report for Android", func(t *testing.T) {
		t.Parallel()
		report := mobilepkg.Report{
			PlatformData: &mobilepkg.AndroidReport{
				RawManifest: map[string]any{"package": "com.test"},
			},
		}
		ar, ok := mobilepkg.AsAndroid(report)
		if !ok {
			t.Fatal("AsAndroid returned false")
		}
		if ar.RawManifest["package"] != "com.test" {
			t.Errorf("RawManifest[package] = %v, want %q", ar.RawManifest["package"], "com.test")
		}
	})

	t.Run("returns false for iOS report", func(t *testing.T) {
		t.Parallel()
		report := mobilepkg.Report{
			PlatformData: &mobilepkg.IOSReport{},
		}
		_, ok := mobilepkg.AsAndroid(report)
		if ok {
			t.Error("AsAndroid should return false for iOS report")
		}
	})

	t.Run("returns false for nil platform data", func(t *testing.T) {
		t.Parallel()
		report := mobilepkg.Report{}
		_, ok := mobilepkg.AsAndroid(report)
		if ok {
			t.Error("AsAndroid should return false for nil PlatformData")
		}
	})
}

func TestAsIOS(t *testing.T) {
	t.Parallel()

	t.Run("returns typed report for iOS", func(t *testing.T) {
		t.Parallel()
		report := mobilepkg.Report{
			PlatformData: &mobilepkg.IOSReport{
				InfoPlist: map[string]any{"CFBundleIdentifier": "com.test"},
			},
		}
		ir, ok := mobilepkg.AsIOS(report)
		if !ok {
			t.Fatal("AsIOS returned false")
		}
		if ir.InfoPlist["CFBundleIdentifier"] != "com.test" {
			t.Errorf("InfoPlist[CFBundleIdentifier] = %v, want %q",
				ir.InfoPlist["CFBundleIdentifier"], "com.test")
		}
	})

	t.Run("returns false for Android report", func(t *testing.T) {
		t.Parallel()
		report := mobilepkg.Report{
			PlatformData: &mobilepkg.AndroidReport{},
		}
		_, ok := mobilepkg.AsIOS(report)
		if ok {
			t.Error("AsIOS should return false for Android report")
		}
	})
}
