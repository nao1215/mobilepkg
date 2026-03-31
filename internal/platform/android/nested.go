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
// candidate names and returns a *zip.Reader for it. If validate is
// non-nil, it is called on the inner archive before returning it.
func findNestedAPK(zr *zip.Reader, candidates []string, maxBytes int64, validate InnerArchiveValidator) (*zip.Reader, error) {
	for _, name := range candidates {
		inner, err := openNestedZip(zr, name, maxBytes)
		if err == nil {
			if validate != nil {
				if vErr := validate(inner); vErr != nil {
					return nil, fmt.Errorf("nested zip %q: validation failed: %w", name, vErr)
				}
			}
			return inner, nil
		}
	}
	return nil, fmt.Errorf("no APK found among candidates: %s", strings.Join(candidates, ", "))
}

// NamedZipReader pairs a zip.Reader with the archive entry name it was
// opened from (e.g. "base.apk", "splits/base-master.apk").
type NamedZipReader struct {
	Name   string
	Reader *zip.Reader
}

// InnerArchiveValidator is a callback that validates an inner zip.Reader
// before it is used for parsing. The caller provides an implementation
// that applies archive safety checks (entry count, paths, compression
// ratio, etc.). A nil validator means no validation is performed.
type InnerArchiveValidator func(zr *zip.Reader) error

// maxInnerAPKs is the maximum number of inner APK entries that
// OpenAllInnerAPKs will process. This prevents a crafted bundle with
// thousands of split APKs from consuming unbounded memory.
const maxInnerAPKs = 200

// OpenAllInnerAPKs opens every .apk entry inside the outer archive,
// returning named readers and diagnostics for any that failed to open.
// At most [maxInnerAPKs] inner APKs are opened; additional entries are
// reported as diagnostics.
func OpenAllInnerAPKs(zr *zip.Reader, maxEntryBytes int64) ([]NamedZipReader, []Diagnostic) {
	seen := make(map[string]struct{})
	var readers []NamedZipReader
	var diags []Diagnostic
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".apk") {
			continue
		}
		if _, ok := seen[f.Name]; ok {
			continue
		}
		seen[f.Name] = struct{}{}
		if len(readers) >= maxInnerAPKs {
			diags = append(diags, Diagnostic{
				Code:     "dex.too_many_inner_apks",
				Severity: "warn",
				Message:  fmt.Sprintf("inner APK count exceeds limit %d; skipping remaining entries", maxInnerAPKs),
			})
			break
		}
		inner, err := openNestedZip(zr, f.Name, maxEntryBytes)
		if err != nil {
			diags = append(diags, Diagnostic{
				Code:     "dex.split_open_failed",
				Severity: "warn",
				Message:  fmt.Sprintf("failed to open inner APK %s for DEX scanning: %v", f.Name, err),
			})
			continue
		}
		readers = append(readers, NamedZipReader{Name: f.Name, Reader: inner})
	}
	return readers, diags
}
