package android

import (
	"archive/zip"
	"fmt"
	"strings"
)

// InspectAPKS extracts information from an APKS (bundletool output) archive.
// It locates the base-master split APK and delegates to the standard APK
// inspector for full analysis. If validate is non-nil, it is called on
// the inner base APK archive before parsing.
func InspectAPKS(zr *zip.Reader, sections uint64, maxEntryBytes int64, validate InnerArchiveValidator) (*Result, []Diagnostic, error) {
	baseZR, err := findBaseMasterAPK(zr, maxEntryBytes, validate)
	if err != nil {
		return nil, nil, fmt.Errorf("android/apks: %w", err)
	}
	return Inspect(baseZR, sections, nil, 0, maxEntryBytes)
}

// findBaseMasterAPK locates the base APK within an APKS archive.
// It tries well-known paths in order of likelihood. If validate is
// non-nil, it is called on the inner archive before returning it.
func findBaseMasterAPK(zr *zip.Reader, maxEntryBytes int64, validate InnerArchiveValidator) (*zip.Reader, error) {
	candidates := []string{"splits/base-master.apk"}

	// Fallback: any base*.apk in splits/
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "splits/base") && strings.HasSuffix(f.Name, ".apk") {
			candidates = append(candidates, f.Name)
		}
	}

	// Last resort: universal.apk (bundletool --mode=universal output)
	candidates = append(candidates, "universal.apk")

	return findNestedAPK(zr, candidates, maxEntryBytes, validate)
}
