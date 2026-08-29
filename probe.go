package mobilepkg

import (
	"archive/zip"
	"strings"
)

// probeResult holds the lightweight detection result used internally
// by [Inspect] to route to the correct platform adapter.
type probeResult struct {
	Platform  Platform
	Format    Format
	Container string
	Hints     []string
}

// probeZip inspects the entries of a ZIP reader and returns a probeResult.
// Detection priority (most specific first): AAB > APKS > XAPK > APK > IPA.
func probeZip(zr *zip.Reader) probeResult {
	result := probeResult{
		Platform:  PlatformUnknown,
		Format:    FormatUnknown,
		Container: "zip",
	}

	var (
		hasRootAndroidManifest bool
		hasInfoPlist           bool
		hasManifestJSON        bool
		hasRootLevelAPK        bool
		hasTocPB               bool
		hasSplitsAPK           bool
		hasBaseManifest        bool // base/manifest/AndroidManifest.xml
		hasBundleConfig        bool // BundleConfig.pb
	)

	for _, f := range zr.File {
		name := f.Name

		switch {
		case name == pathAndroidManifest:
			hasRootAndroidManifest = true
		case name == "manifest.json":
			hasManifestJSON = true
		case name == "toc.pb":
			hasTocPB = true
		case name == "BundleConfig.pb":
			hasBundleConfig = true
		case name == "base/manifest/AndroidManifest.xml":
			hasBaseManifest = true
		case strings.HasPrefix(name, "Payload/") && strings.HasSuffix(name, ".app/Info.plist"):
			hasInfoPlist = true
		}

		// Root-level .apk file (no directory separator) for XAPK detection
		if strings.HasSuffix(name, ".apk") && !strings.Contains(name, "/") {
			hasRootLevelAPK = true
		}

		// splits/*.apk for APKS detection
		if strings.HasPrefix(name, "splits/") && strings.HasSuffix(name, ".apk") {
			hasSplitsAPK = true
		}
	}

	// Determine format — most specific first
	switch {
	case hasBaseManifest && hasBundleConfig:
		result.Platform = PlatformAndroid
		result.Format = FormatAAB
		result.Hints = append(result.Hints, "has base/manifest/AndroidManifest.xml", "has BundleConfig.pb")

	case hasTocPB && hasSplitsAPK:
		result.Platform = PlatformAndroid
		result.Format = FormatAPKS
		result.Hints = append(result.Hints, "has toc.pb", "has splits/*.apk")

	case hasManifestJSON && hasRootLevelAPK && !hasRootAndroidManifest:
		result.Platform = PlatformAndroid
		result.Format = FormatXAPK
		result.Hints = append(result.Hints, "has manifest.json", "has inner .apk")

	case hasRootAndroidManifest:
		result.Platform = PlatformAndroid
		result.Format = FormatAPK
		result.Hints = append(result.Hints, "has AndroidManifest.xml")

	case hasInfoPlist:
		result.Platform = PlatformIOS
		result.Format = FormatIPA
		result.Hints = append(result.Hints, "has Info.plist")
	}

	return result
}
