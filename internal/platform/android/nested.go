package android

import (
	"archive/zip"
	"bytes"
	"errors"
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
// Candidates that fail to open or fail validation are skipped so that
// subsequent candidates still get a chance.
func findNestedAPK(zr *zip.Reader, candidates []string, maxBytes int64, validate InnerArchiveValidator) (*zip.Reader, error) {
	for _, name := range candidates {
		inner, err := openNestedZip(zr, name, maxBytes)
		if err != nil {
			continue
		}
		if validate != nil {
			if vErr := validate(inner); vErr != nil {
				continue
			}
		}
		return inner, nil
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

// isConfigSplit returns true if the inner APK name matches the Android
// config split naming convention: "config.<qualifier>.apk" (e.g.
// config.arm64_v8a.apk, config.en.apk, config.xxhdpi.apk). Config splits
// contain only resources and native libraries, never DEX bytecode.
func isConfigSplit(name string) bool {
	lower := strings.ToLower(name)
	// Strip directory prefix (e.g. "splits/config.de.apk" → "config.de.apk").
	if idx := strings.LastIndex(lower, "/"); idx >= 0 {
		lower = lower[idx+1:]
	}
	return strings.HasPrefix(lower, "config.")
}

// containsDEX checks whether a zip.Reader contains at least one
// top-level classes*.dex entry.
func containsDEX(zr *zip.Reader) bool {
	for _, f := range zr.File {
		if strings.Contains(f.Name, "/") {
			continue
		}
		if strings.HasPrefix(f.Name, "classes") && strings.HasSuffix(f.Name, ".dex") {
			return true
		}
	}
	return false
}

// OpenAllInnerAPKs opens every .apk entry inside the outer archive,
// returning named readers and diagnostics for any that failed to open.
// At most [maxInnerAPKs] inner APKs are opened; additional entries are
// reported as diagnostics.
//
// Config splits (config.<qualifier>.apk) are skipped by name since they
// never contain DEX. Other inner APKs that can be opened but contain no
// DEX entries are silently skipped. Inner APKs that exceed the size
// limit produce an info-level diagnostic (they are typically asset or
// OBB splits).
func OpenAllInnerAPKs(zr *zip.Reader, maxEntryBytes int64) ([]NamedZipReader, []Diagnostic) {
	seen := make(map[string]struct{})
	var readers []NamedZipReader
	var diags []Diagnostic
	attempted := 0
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".apk") {
			continue
		}
		if _, ok := seen[f.Name]; ok {
			continue
		}
		seen[f.Name] = struct{}{}
		if isConfigSplit(f.Name) {
			continue
		}
		inner, err := openNestedZip(zr, f.Name, maxEntryBytes)
		if err != nil {
			// Size-limit failures are typically asset/OBB splits with
			// no DEX — report at info to avoid noisy diagnostics.
			// Other failures (corrupt zip, I/O errors) stay at warn
			// because they may indicate a broken code-bearing split.
			sev := sevWarn
			if errors.Is(err, ErrEntryOversize) {
				sev = "info"
			}
			diags = append(diags, Diagnostic{
				Code:     "dex.split_open_failed",
				Severity: sev,
				Message:  fmt.Sprintf("failed to open inner APK %s for DEX scanning: %v", f.Name, err),
			})
			continue
		}
		if !containsDEX(inner) {
			continue
		}
		// Count only DEX-bearing splits against the limit so that
		// non-DEX splits (asset packs, resource-only) do not exhaust
		// the budget before real code splits are reached.
		if attempted >= maxInnerAPKs {
			diags = append(diags, Diagnostic{
				Code:     "dex.too_many_inner_apks",
				Severity: sevWarn,
				Message:  fmt.Sprintf("inner APK count exceeds limit %d; skipping remaining entries", maxInnerAPKs),
			})
			break
		}
		attempted++
		readers = append(readers, NamedZipReader{Name: f.Name, Reader: inner})
	}
	return readers, diags
}
