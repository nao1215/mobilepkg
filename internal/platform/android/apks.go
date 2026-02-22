package android

import (
	"archive/zip"
	"fmt"
	"strings"
)

// InspectAPKS extracts information from an APKS (bundletool output) archive.
// It locates the base-master split APK and delegates to the standard APK
// inspector for full analysis.
func InspectAPKS(zr *zip.Reader, sections uint64, maxEntryBytes int64) (*Result, []Diagnostic, error) {
	baseZR, err := findBaseMasterAPK(zr, maxEntryBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("android/apks: %w", err)
	}
	return Inspect(baseZR, sections, nil, 0, maxEntryBytes)
}

// findBaseMasterAPK locates the base APK within an APKS archive.
// It tries well-known paths in order of likelihood.
func findBaseMasterAPK(zr *zip.Reader, maxEntryBytes int64) (*zip.Reader, error) {
	// Primary: exact name used by bundletool
	if inner, err := openNestedZip(zr, "splits/base-master.apk", maxEntryBytes); err == nil {
		return inner, nil
	}

	// Fallback: any base*.apk in splits/
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "splits/base") && strings.HasSuffix(f.Name, ".apk") {
			if inner, err := openNestedZip(zr, f.Name, maxEntryBytes); err == nil {
				return inner, nil
			}
		}
	}

	// Last resort: universal.apk (bundletool --mode=universal output)
	if inner, err := openNestedZip(zr, "universal.apk", maxEntryBytes); err == nil {
		return inner, nil
	}

	return nil, fmt.Errorf("no base APK found in APKS archive")
}
