package mobilepkg

import (
	"archive/zip"
	"fmt"
	"os"
	"path"
	"strings"
)

// validateArchive checks the ZIP archive against the given safety limits.
// It validates entry count, total/single entry sizes, path names, symlinks,
// and compression ratios. The depth parameter tracks the current nesting
// level for nested archives (0 for top-level).
//
// This function inspects ZIP directory metadata only and does not decompress
// any entries. Actual decompression limits must be enforced separately at
// read time via bounded readers.
func validateArchive(zr *zip.Reader, inputSize int64, limits ArchiveLimits, depth int) error {
	if limits.MaxInputBytes > 0 && inputSize > limits.MaxInputBytes {
		return fmt.Errorf("%w: input size %d exceeds limit %d", ErrOversize, inputSize, limits.MaxInputBytes)
	}

	if limits.MaxNestingDepth > 0 && depth > limits.MaxNestingDepth {
		return fmt.Errorf("%w: depth %d exceeds limit %d", ErrTooDeep, depth, limits.MaxNestingDepth)
	}

	if limits.MaxEntryCount > 0 && len(zr.File) > limits.MaxEntryCount {
		return fmt.Errorf("%w: %d entries exceed limit %d", ErrTooManyFiles, len(zr.File), limits.MaxEntryCount)
	}

	seen := make(map[string]struct{}, len(zr.File))

	for _, f := range zr.File {
		if err := validateEntryName(f.Name, limits); err != nil {
			return err
		}

		// Check for duplicate normalized paths.
		normalized := path.Clean(f.Name)
		if _, exists := seen[normalized]; exists {
			return fmt.Errorf("%w: duplicate normalized path %q", ErrInvalidName, normalized)
		}
		seen[normalized] = struct{}{}

		// Check symlinks.
		if !limits.AllowSymlinks && f.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: entry %q is a symlink", ErrSymlink, f.Name)
		}

		// NOTE: Single entry and total uncompressed size checks are
		// intentionally NOT applied to ZIP directory metadata here.
		// The declared UncompressedSize64 is attacker-controlled and
		// many legitimate packages (e.g. XAPK with OBB files) contain
		// entries larger than any safe default. The real defense is
		// io.LimitReader enforcement inside readZipFile, which bounds
		// actual decompression. The metadata-level checks below only
		// cover compression ratio (a reliable zip-bomb indicator).

		// Check compression ratio.
		if limits.MaxCompressionRatio > 0 && f.CompressedSize64 > 0 {
			ratio := float64(f.UncompressedSize64) / float64(f.CompressedSize64)
			if ratio > limits.MaxCompressionRatio {
				return fmt.Errorf("%w: entry %q ratio %.1f exceeds limit %.1f",
					ErrCompressionRatioExceeded, f.Name, ratio, limits.MaxCompressionRatio)
			}
		}
	}

	return nil
}

// validateEntryName checks a single ZIP entry name for safety issues:
// NUL bytes, control characters, absolute paths, path traversal,
// backslashes, and excessive length.
func validateEntryName(name string, limits ArchiveLimits) error {
	if limits.MaxPathLength > 0 && len(name) > limits.MaxPathLength {
		return fmt.Errorf("%w: path length %d exceeds limit %d", ErrInvalidName, len(name), limits.MaxPathLength)
	}

	if strings.ContainsRune(name, 0) {
		return fmt.Errorf("%w: entry name contains NUL byte", ErrInvalidName)
	}

	if containsControlChars(name) {
		return fmt.Errorf("%w: entry name contains control characters", ErrInvalidName)
	}

	// Reject backslashes — they can be used for path traversal on Windows.
	if strings.ContainsRune(name, '\\') {
		return fmt.Errorf("%w: entry name contains backslash: %q", ErrInvalidName, name)
	}

	// Reject absolute paths.
	if strings.HasPrefix(name, "/") {
		return fmt.Errorf("%w: entry name is an absolute path: %q", ErrPathTraversal, name)
	}

	// Reject path traversal via ".." components.
	cleaned := path.Clean(name)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return fmt.Errorf("%w: entry name contains traversal: %q", ErrPathTraversal, name)
	}

	return nil
}

// containsControlChars reports whether s contains any control characters
// (Unicode codepoints below 0x20) other than horizontal tab (0x09).
func containsControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 && r != '\t' {
			return true
		}
	}
	return false
}

// effectiveLimits returns the archive limits to use for inspection.
// If opts.Archive is nil, [DefaultArchiveLimits] is returned.
func effectiveLimits(opts InspectOptions) ArchiveLimits {
	if opts.Archive != nil {
		return *opts.Archive
	}
	return DefaultArchiveLimits()
}
