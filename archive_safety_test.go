package mobilepkg_test

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nao1215/mobilepkg"
)

func TestValidateArchive_PathTraversal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		entryName string
	}{
		{"dot-dot component", "../etc/passwd"},
		{"nested dot-dot", "foo/../../etc/passwd"},
		{"absolute path", "/etc/passwd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := createZipWithEntry(t, tt.entryName, []byte("data"))
			_, err := mobilepkg.InspectFile(context.Background(), p)
			if err == nil {
				t.Fatal("expected error for path traversal, got nil")
			}
			if !errors.Is(err, mobilepkg.ErrPathTraversal) {
				t.Fatalf("expected ErrPathTraversal, got: %v", err)
			}
		})
	}
}

func TestValidateArchive_InvalidName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		entryName string
	}{
		{"NUL byte", "foo\x00bar"},
		{"control character", "foo\x01bar"},
		{"backslash", "foo\\bar"},
		{"path too long", strings.Repeat("a", 513)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := createZipWithEntry(t, tt.entryName, []byte("data"))
			_, err := mobilepkg.InspectFile(context.Background(), p)
			if err == nil {
				t.Fatal("expected error for invalid name, got nil")
			}
			if !errors.Is(err, mobilepkg.ErrInvalidName) {
				t.Fatalf("expected ErrInvalidName, got: %v", err)
			}
		})
	}
}

func TestValidateArchive_TooManyFiles(t *testing.T) {
	t.Parallel()

	p := createZipWithNEntries(t, 11)
	limits := mobilepkg.DefaultArchiveLimits()
	limits.MaxEntryCount = 10
	_, err := mobilepkg.InspectFileWithOptions(context.Background(), p, mobilepkg.InspectOptions{
		Archive: &limits,
	})
	if err == nil {
		t.Fatal("expected error for too many files, got nil")
	}
	if !errors.Is(err, mobilepkg.ErrTooManyFiles) {
		t.Fatalf("expected ErrTooManyFiles, got: %v", err)
	}
}

func TestValidateArchive_OversizeInput(t *testing.T) {
	t.Parallel()

	p := createZipWithEntry(t, "a.txt", []byte("hello"))
	limits := mobilepkg.DefaultArchiveLimits()
	limits.MaxInputBytes = 1 // 1 byte limit
	_, err := mobilepkg.InspectFileWithOptions(context.Background(), p, mobilepkg.InspectOptions{
		Archive: &limits,
	})
	if err == nil {
		t.Fatal("expected error for oversize input, got nil")
	}
	if !errors.Is(err, mobilepkg.ErrOversize) {
		t.Fatalf("expected ErrOversize, got: %v", err)
	}
}

func TestValidateArchive_DuplicateNormalizedPath(t *testing.T) {
	t.Parallel()

	p := createZipWithEntries(t, map[string][]byte{
		"foo/bar":  []byte("a"),
		"foo//bar": []byte("b"),
	})
	_, err := mobilepkg.InspectFile(context.Background(), p)
	if err == nil {
		t.Fatal("expected error for duplicate normalized path, got nil")
	}
	if !errors.Is(err, mobilepkg.ErrInvalidName) {
		t.Fatalf("expected ErrInvalidName, got: %v", err)
	}
}

func TestValidateArchive_SymlinkRejected(t *testing.T) {
	t.Parallel()

	p := createZipWithSymlink(t, "link.txt", "target.txt")
	_, err := mobilepkg.InspectFile(context.Background(), p)
	if err == nil {
		t.Fatal("expected error for symlink, got nil")
	}
	if !errors.Is(err, mobilepkg.ErrSymlink) {
		t.Fatalf("expected ErrSymlink, got: %v", err)
	}
}

func TestValidateArchive_SymlinkAllowed(t *testing.T) {
	t.Parallel()

	p := createZipWithSymlink(t, "link.txt", "target.txt")
	limits := mobilepkg.DefaultArchiveLimits()
	limits.AllowSymlinks = true
	// This will still fail (unsupported format) but should NOT fail
	// on symlink validation.
	_, err := mobilepkg.InspectFileWithOptions(context.Background(), p, mobilepkg.InspectOptions{
		Archive: &limits,
	})
	if errors.Is(err, mobilepkg.ErrSymlink) {
		t.Fatal("symlinks should be allowed but got ErrSymlink")
	}
}

func TestValidateArchive_CompressionRatioExceeded(t *testing.T) {
	t.Parallel()

	// Create a zip with highly compressible content.
	p := createZipWithEntry(t, "bomb.txt", bytes.Repeat([]byte{0}, 10*1024))
	limits := mobilepkg.DefaultArchiveLimits()
	limits.MaxCompressionRatio = 1.5
	_, err := mobilepkg.InspectFileWithOptions(context.Background(), p, mobilepkg.InspectOptions{
		Archive: &limits,
	})
	if err == nil {
		t.Fatal("expected error for compression ratio, got nil")
	}
	if !errors.Is(err, mobilepkg.ErrCompressionRatioExceeded) {
		t.Fatalf("expected ErrCompressionRatioExceeded, got: %v", err)
	}
}

func TestValidateArchive_ValidArchivePassesDefaults(t *testing.T) {
	t.Parallel()

	p := createZipWithEntry(t, "hello.txt", []byte("hello world"))
	// Should not error on validation (will error on format, which is fine).
	_, err := mobilepkg.InspectFile(context.Background(), p)
	if err == nil {
		// An empty zip with just hello.txt is not a valid APK/IPA, so we
		// expect an error — but it should be format-related, not safety.
		t.Fatal("expected unsupported format error")
	}
	if errors.Is(err, mobilepkg.ErrPathTraversal) ||
		errors.Is(err, mobilepkg.ErrTooManyFiles) ||
		errors.Is(err, mobilepkg.ErrOversize) ||
		errors.Is(err, mobilepkg.ErrTooDeep) ||
		errors.Is(err, mobilepkg.ErrCompressionRatioExceeded) ||
		errors.Is(err, mobilepkg.ErrSymlink) ||
		errors.Is(err, mobilepkg.ErrInvalidName) {
		t.Fatalf("expected format error, got safety error: %v", err)
	}
}

func TestValidateArchive_NoLimits(t *testing.T) {
	t.Parallel()

	p := createZipWithEntry(t, "hello.txt", []byte("hello"))
	noLimits := mobilepkg.ArchiveLimits{}
	_, err := mobilepkg.InspectFileWithOptions(context.Background(), p, mobilepkg.InspectOptions{
		Archive: &noLimits,
	})
	// Should fail on format, not on safety limits.
	if errors.Is(err, mobilepkg.ErrOversize) ||
		errors.Is(err, mobilepkg.ErrTooManyFiles) {
		t.Fatalf("expected no safety error with zero limits, got: %v", err)
	}
}

func TestDefaultArchiveLimits(t *testing.T) {
	t.Parallel()

	limits := mobilepkg.DefaultArchiveLimits()
	if limits.MaxInputBytes != 2<<30 {
		t.Errorf("MaxInputBytes = %d, want %d", limits.MaxInputBytes, 2<<30)
	}
	if limits.MaxEntryCount != 100_000 {
		t.Errorf("MaxEntryCount = %d, want %d", limits.MaxEntryCount, 100_000)
	}
	if limits.MaxTotalUncompressedBytes != 4<<30 {
		t.Errorf("MaxTotalUncompressedBytes = %d, want %d", limits.MaxTotalUncompressedBytes, 4<<30)
	}
	if limits.MaxSingleEntryUncompressedBytes != 512<<20 {
		t.Errorf("MaxSingleEntryUncompressedBytes = %d, want %d", limits.MaxSingleEntryUncompressedBytes, 512<<20)
	}
	if limits.MaxNestingDepth != 4 {
		t.Errorf("MaxNestingDepth = %d, want %d", limits.MaxNestingDepth, 4)
	}
	if limits.MaxPathLength != 512 {
		t.Errorf("MaxPathLength = %d, want %d", limits.MaxPathLength, 512)
	}
	if limits.MaxCompressionRatio != 100 {
		t.Errorf("MaxCompressionRatio = %f, want %f", limits.MaxCompressionRatio, 100.0)
	}
	if limits.AllowSymlinks {
		t.Error("AllowSymlinks should be false by default")
	}
}

func TestInspectErrorCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		sentinel     error
		expectedCode string
	}{
		{"path traversal", mobilepkg.ErrPathTraversal, "archive.path_traversal"},
		{"too many files", mobilepkg.ErrTooManyFiles, "archive.too_many_files"},
		{"oversize", mobilepkg.ErrOversize, "archive.oversize"},
		{"too deep", mobilepkg.ErrTooDeep, "archive.too_deep"},
		{"compression ratio", mobilepkg.ErrCompressionRatioExceeded, "archive.compression_ratio_exceeded"},
		{"symlink", mobilepkg.ErrSymlink, "archive.symlink"},
		{"invalid name", mobilepkg.ErrInvalidName, "archive.invalid_name"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var p string
			if errors.Is(tt.sentinel, mobilepkg.ErrPathTraversal) {
				p = createZipWithEntry(t, "../evil", []byte("x"))
			} else if errors.Is(tt.sentinel, mobilepkg.ErrTooManyFiles) {
				p = createZipWithNEntries(t, 3)
				limits := mobilepkg.DefaultArchiveLimits()
				limits.MaxEntryCount = 2
				_, err := mobilepkg.InspectFileWithOptions(context.Background(), p, mobilepkg.InspectOptions{Archive: &limits})
				if err == nil {
					t.Fatal("expected error")
				}
				var ie *mobilepkg.InspectError
				if !errors.As(err, &ie) {
					t.Fatalf("expected InspectError, got %T", err)
				}
				if ie.Code != tt.expectedCode {
					t.Errorf("code = %q, want %q", ie.Code, tt.expectedCode)
				}
				return
			} else if errors.Is(tt.sentinel, mobilepkg.ErrOversize) {
				p = createZipWithEntry(t, "a.txt", []byte("hello"))
				limits := mobilepkg.DefaultArchiveLimits()
				limits.MaxInputBytes = 1
				_, err := mobilepkg.InspectFileWithOptions(context.Background(), p, mobilepkg.InspectOptions{Archive: &limits})
				if err == nil {
					t.Fatal("expected error")
				}
				var ie *mobilepkg.InspectError
				if !errors.As(err, &ie) {
					t.Fatalf("expected InspectError, got %T", err)
				}
				if ie.Code != tt.expectedCode {
					t.Errorf("code = %q, want %q", ie.Code, tt.expectedCode)
				}
				return
			} else if errors.Is(tt.sentinel, mobilepkg.ErrSymlink) {
				p = createZipWithSymlink(t, "link", "target")
			} else if errors.Is(tt.sentinel, mobilepkg.ErrInvalidName) {
				p = createZipWithEntry(t, "foo\x00bar", []byte("x"))
			} else {
				t.Skip("test case not implemented")
				return
			}

			_, err := mobilepkg.InspectFile(context.Background(), p)
			if err == nil {
				t.Fatal("expected error")
			}
			var ie *mobilepkg.InspectError
			if !errors.As(err, &ie) {
				t.Fatalf("expected InspectError, got %T", err)
			}
			if ie.Code != tt.expectedCode {
				t.Errorf("code = %q, want %q", ie.Code, tt.expectedCode)
			}
		})
	}
}

// --- test helpers ---

func createZipWithEntry(t *testing.T, name string, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "test.zip")
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	fw, err := w.Create(name)
	if err != nil {
		t.Fatalf("create entry: %v", err)
	}
	if _, err := fw.Write(data); err != nil {
		t.Fatalf("write entry: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return p
}

func createZipWithEntries(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "test.zip")
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, data := range entries {
		fw, err := w.CreateHeader(&zip.FileHeader{Name: name})
		if err != nil {
			t.Fatalf("create entry %q: %v", name, err)
		}
		if _, err := fw.Write(data); err != nil {
			t.Fatalf("write entry %q: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return p
}

func createZipWithNEntries(t *testing.T, n int) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "test.zip")
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for i := range n {
		name := "entry_" + padInt(i) + ".txt"
		fw, err := w.Create(name)
		if err != nil {
			t.Fatalf("create entry %d: %v", i, err)
		}
		if _, err := fw.Write([]byte("data")); err != nil {
			t.Fatalf("write entry %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return p
}

func padInt(i int) string {
	return fmt.Sprintf("%05d", i)
}

func createZipWithSymlink(t *testing.T, name, target string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "test.zip")
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	hdr := &zip.FileHeader{
		Name: name,
	}
	hdr.SetMode(os.ModeSymlink | 0o777)
	fw, err := w.CreateHeader(hdr)
	if err != nil {
		t.Fatalf("create symlink entry: %v", err)
	}
	if _, err := fw.Write([]byte(target)); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return p
}
