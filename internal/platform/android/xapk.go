package android

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"strings"
)

// xapkManifest represents the manifest.json found in XAPK files.
type xapkManifest struct {
	XAPKVersion int      `json:"xapk_version"`
	PackageName string   `json:"package_name"`
	Name        string   `json:"name"`
	VersionCode any      `json:"version_code"` // can be int or string
	VersionName string   `json:"version_name"`
	Permissions []string `json:"permissions"`
	SplitAPKs   []struct {
		File string `json:"file"`
		ID   string `json:"id"`
	} `json:"split_apks"`
}

// InspectXAPK extracts information from an XAPK archive.
// It parses manifest.json for quick metadata and delegates to the standard
// APK inspector for deeper analysis of the base APK inside.
// If validate is non-nil, it is called on the inner base APK archive
// before parsing its manifest and resources.
func InspectXAPK(zr *zip.Reader, sections uint64, maxEntryBytes int64, validate InnerArchiveValidator) (*Result, []Diagnostic, error) {
	manifestData, err := readZipFile(zr, "manifest.json", maxEntryBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("android/xapk: %w", err)
	}

	var xm xapkManifest
	if err := json.Unmarshal(manifestData, &xm); err != nil {
		return nil, nil, fmt.Errorf("android/xapk: failed to parse manifest.json: %w", err)
	}

	// Try to find and open the base APK for deeper inspection.
	baseZR, baseErr := findXAPKBaseAPK(zr, xm, maxEntryBytes, validate)
	if baseErr == nil {
		innerResult, innerDiags, innerErr := Inspect(baseZR, sections, nil, 0, maxEntryBytes)
		if innerErr == nil {
			mergeXAPKMetadata(innerResult, xm, sections)
			return innerResult, innerDiags, nil
		}
	}

	// Fallback: extract what we can from manifest.json alone.
	return resultFromXAPKManifest(xm, sections), nil, nil
}

// findXAPKBaseAPK locates the base APK inside an XAPK archive.
func findXAPKBaseAPK(zr *zip.Reader, xm xapkManifest, maxEntryBytes int64, validate InnerArchiveValidator) (*zip.Reader, error) {
	var candidates []string

	// v2: look at split_apks for the base entry
	for _, s := range xm.SplitAPKs {
		if s.ID == "base" {
			candidates = append(candidates, s.File)
		}
	}

	// common names
	candidates = append(candidates, "base.apk")
	if xm.PackageName != "" {
		candidates = append(candidates, xm.PackageName+".apk")
	}

	// last resort: any root-level .apk
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, ".apk") && !strings.Contains(f.Name, "/") {
			candidates = append(candidates, f.Name)
		}
	}

	return findNestedAPK(zr, candidates, maxEntryBytes, validate)
}

// mergeXAPKMetadata fills in any fields that the base APK inspection
// might have missed, using data from the XAPK manifest.json.
func mergeXAPKMetadata(result *Result, xm xapkManifest, sections uint64) {
	const (
		bitIdentity    = 0
		bitVersion     = 1
		bitPermissions = 3
	)

	if sections&(1<<bitIdentity) != 0 {
		if result.PackageName == "" {
			result.PackageName = xm.PackageName
		}
		if result.Label == "" {
			result.Label = xm.Name
		}
	}

	if sections&(1<<bitVersion) != 0 {
		if result.VersionName == "" {
			result.VersionName = xm.VersionName
		}
		if result.VersionCode == "" {
			result.VersionCode = fmt.Sprintf("%v", xm.VersionCode)
		}
	}

	if sections&(1<<bitPermissions) != 0 && len(result.Permissions) == 0 {
		result.Permissions = xm.Permissions
	}
}

// resultFromXAPKManifest creates a Result from manifest.json alone
// when the inner base APK cannot be parsed.
func resultFromXAPKManifest(xm xapkManifest, sections uint64) *Result {
	result := &Result{}

	const (
		bitIdentity    = 0
		bitVersion     = 1
		bitPermissions = 3
		bitPlatformRaw = 5
	)

	if sections&(1<<bitIdentity) != 0 {
		result.PackageName = xm.PackageName
		result.Label = xm.Name
	}

	if sections&(1<<bitVersion) != 0 {
		result.VersionName = xm.VersionName
		result.VersionCode = fmt.Sprintf("%v", xm.VersionCode)
	}

	if sections&(1<<bitPermissions) != 0 {
		result.Permissions = xm.Permissions
	}

	if sections&(1<<bitPlatformRaw) != 0 {
		result.RawManifest = map[string]any{
			"package":     xm.PackageName,
			"versionCode": fmt.Sprintf("%v", xm.VersionCode),
			"versionName": xm.VersionName,
		}
	}

	return result
}
