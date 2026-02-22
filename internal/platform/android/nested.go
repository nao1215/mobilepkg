package android

import (
	"archive/zip"
	"bytes"
	"fmt"
	"strings"
)

// openNestedZip reads a ZIP file entry from the outer archive and returns
// a *zip.Reader for the inner archive. The entire inner archive is read
// into memory.
func openNestedZip(zr *zip.Reader, name string, maxBytes int64) (*zip.Reader, error) {
	data, err := readZipFile(zr, name, maxBytes)
	if err != nil {
		return nil, fmt.Errorf("nested zip %q: %w", name, err)
	}
	r := bytes.NewReader(data)
	inner, err := zip.NewReader(r, int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("nested zip %q: invalid zip: %w", name, err)
	}
	return inner, nil
}

// findNestedAPK searches for the first APK file matching any of the given
// candidate names and returns a *zip.Reader for it.
func findNestedAPK(zr *zip.Reader, candidates []string, maxBytes int64) (*zip.Reader, error) {
	for _, name := range candidates {
		inner, err := openNestedZip(zr, name, maxBytes)
		if err == nil {
			return inner, nil
		}
	}
	return nil, fmt.Errorf("no APK found among candidates: %s", strings.Join(candidates, ", "))
}
