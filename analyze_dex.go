package mobilepkg

import (
	"archive/zip"
	"fmt"
	"io"
	"strings"

	"github.com/nao1215/mobilepkg/internal/dex"
	"github.com/nao1215/mobilepkg/internal/scanner"
)

// analyzeDex reads DEX files from all provided archives, parses them, runs
// the security scanner, and returns findings. Parsed DEX data is local to
// this function and eligible for GC on return.
func analyzeDex(readers []namedReader, format Format, maxEntryBytes int64) ([]Finding, []Diagnostic) {
	var dexEntries []dexEntry
	var diags []Diagnostic
	for _, nr := range readers {
		entries, d := readDexFiles(nr.reader, nr.label, format, maxEntryBytes)
		dexEntries = append(dexEntries, entries...)
		diags = append(diags, d...)
	}
	if len(dexEntries) == 0 {
		return nil, diags
	}

	ctx := &scanner.Context{
		DexFiles: make([]*dex.File, len(dexEntries)),
		DexNames: make([]string, len(dexEntries)),
	}
	for i, de := range dexEntries {
		ctx.DexFiles[i] = de.file
		ctx.DexNames[i] = de.name
	}

	scanFindings := scanner.Scan(ctx)

	findings := make([]Finding, 0, len(scanFindings))
	for _, sf := range scanFindings {
		findings = append(findings, Finding{
			ID:         sf.ID,
			Category:   sf.Category,
			Severity:   Severity(sf.Severity),
			Confidence: Confidence(sf.Confidence),
			Message:    sf.Message,
			Evidence: []Evidence{{
				ArchivePath:       sf.ArchivePath,
				Field:             sf.Field,
				MatchedTextMasked: maskSecret(sf.Matched),
				Offset:            sf.Offset,
			}},
			Fingerprint: fingerprint(sf.Category, sf.ID),
		})
	}
	return findings, diags
}

// dexEntry pairs a parsed DEX file with its qualified archive path.
type dexEntry struct {
	// name is the qualified path, e.g. "classes.dex" for a plain APK,
	// "base.apk!/classes2.dex" for a split inside XAPK/APKS,
	// or "base/dex/classes.dex" for AAB.
	name string
	file *dex.File
}

// qualifyDexName prefixes a DEX entry name with the split APK label
// when the DEX comes from a nested archive. For top-level archives
// (empty label), the name is returned unchanged.
func qualifyDexName(splitLabel, dexName string) string {
	if splitLabel == "" {
		return dexName
	}
	return splitLabel + "!/" + dexName
}

// readDexFiles reads and parses all DEX files from the ZIP archive.
// splitLabel is the name of the containing archive (e.g. "base.apk")
// and is used to qualify the entry name. Empty for top-level archives.
func readDexFiles(zr *zip.Reader, splitLabel string, format Format, maxEntryBytes int64) ([]dexEntry, []Diagnostic) {
	var entries []dexEntry
	var diags []Diagnostic

	for _, f := range zr.File {
		if !isDexEntry(f.Name, format) {
			continue
		}

		data, err := readZipEntry(f, maxEntryBytes)
		if err != nil {
			diags = append(diags, Diagnostic{
				Code:     "dex.read_failed",
				Severity: SeverityWarn,
				Message:  fmt.Sprintf("failed to read %s: %v", qualifyDexName(splitLabel, f.Name), err),
			})
			continue
		}

		df, err := dex.Parse(data)
		if err != nil {
			diags = append(diags, Diagnostic{
				Code:     "dex.parse_failed",
				Severity: SeverityWarn,
				Message:  fmt.Sprintf("failed to parse %s: %v", qualifyDexName(splitLabel, f.Name), err),
			})
			continue
		}
		entries = append(entries, dexEntry{name: qualifyDexName(splitLabel, f.Name), file: df})
	}
	return entries, diags
}

// isDexEntry returns true if the ZIP entry name is a DEX file for the given format.
func isDexEntry(name string, format Format) bool {
	switch format {
	case FormatAAB:
		// AAB: <module>/dex/classes*.dex (base, dynamic features, etc.)
		parts := strings.Split(name, "/")
		if len(parts) != 3 || parts[1] != "dex" {
			return false
		}
		return strings.HasPrefix(parts[2], "classes") &&
			strings.HasSuffix(parts[2], ".dex")
	default:
		// APK/XAPK/APKS: classes.dex at root
		if strings.Contains(name, "/") {
			return false
		}
		return strings.HasPrefix(name, "classes") && strings.HasSuffix(name, ".dex")
	}
}

// readZipEntry safely reads a ZIP entry using io.LimitReader to enforce
// the size limit at the read level, consistent with the project's archive
// safety model (see archive_safety.go).
func readZipEntry(f *zip.File, maxBytes int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()

	if maxBytes > 0 {
		limited := io.LimitReader(rc, maxBytes+1)
		data, err := io.ReadAll(limited)
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > maxBytes {
			return nil, fmt.Errorf("entry %q exceeds size limit of %d bytes", f.Name, maxBytes)
		}
		return data, nil
	}
	return io.ReadAll(rc)
}
