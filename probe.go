package mobilepkg

import (
	"archive/zip"
	"io"
	"os"
	"strings"
)

// Probe performs a lightweight detection of the mobile platform and
// packaging format from the given [io.ReaderAt]. This is useful when the
// package is already in memory or comes from a non-file source.
//
// Probe does not fully parse the package; use [Inspect] for that.
func Probe(r io.ReaderAt, size int64) (ProbeResult, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return ProbeResult{}, ErrUnsupportedFormat
	}
	return probeZip(zr), nil
}

// ProbeFile performs a lightweight detection of the mobile platform and
// packaging format from the file at the given path. It opens the file as a
// ZIP archive and looks for well-known entries to determine whether it is
// an APK, XAPK, APKS, AAB, or IPA.
//
// ProbeFile does not fully parse the package; use [InspectFile] for that.
func ProbeFile(path string) (ProbeResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return ProbeResult{}, err
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return ProbeResult{}, err
	}

	return Probe(f, fi.Size())
}

// probeZip inspects the entries of a ZIP reader and returns a ProbeResult.
// Detection priority (most specific first): AAB > APKS > XAPK > APK > IPA.
func probeZip(zr *zip.Reader) ProbeResult {
	result := ProbeResult{
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
		case name == "AndroidManifest.xml":
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
