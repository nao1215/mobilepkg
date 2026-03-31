package mobilepkg

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/nao1215/mobilepkg/internal/platform/android"
	"github.com/nao1215/mobilepkg/internal/platform/ios"
)

// InspectFile performs a complete inspection of the mobile package at
// the given path. It extracts all available metadata, runs security
// analysis, and returns a unified [InspectResult]. No options are needed
// for the primary path — sensible defaults are applied automatically.
//
// This is the primary entry point for the mobilepkg API. For expert
// use cases that need to control archive limits or icon size, use
// [InspectFileWithOptions] instead.
//
// Example:
//
//	result, err := mobilepkg.InspectFile(ctx, "app.apk")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(result.Identity.Identifier)
//	for _, f := range result.Findings {
//	    fmt.Printf("[%s] %s\n", f.Severity, f.Message)
//	}
func InspectFile(ctx context.Context, path string) (*InspectResult, error) {
	return InspectFileWithOptions(ctx, path, InspectOptions{})
}

// InspectFileWithOptions performs a complete inspection of the mobile
// package at the given path with the specified options. It extracts all
// available metadata, runs security analysis, and returns a unified
// [InspectResult].
//
// Use this when you need to control archive safety limits. For most
// callers, [InspectFile] is sufficient.
func InspectFileWithOptions(ctx context.Context, path string, opts InspectOptions) (*InspectResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	f, ext, err := extractReportFromFile(ctx, path, opts)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	analysis := analyzeReport(ext.report, analyzeOptions{
		dexReaders:    ext.dexReaders,
		maxEntryBytes: ext.maxEntryBytes,
	})

	return buildInspectResult(ext.report, analysis), nil
}

// InspectWithBaseline performs a complete inspection and compares the
// result against a previous [InspectResult]. The baseline diff is
// included in the returned result.
//
// This is useful for release-diff scenarios where you want to detect
// added/removed permissions, version bumps, or new security findings
// between two builds.
func InspectWithBaseline(ctx context.Context, path string, baseline *InspectResult) (*InspectResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	f, ext, err := extractReportFromFile(ctx, path, InspectOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	// Convert baseline InspectResult to Report for internal comparison.
	baselineReport := inspectResultToReport(baseline)
	analysis := analyzeReport(ext.report, analyzeOptions{
		baseline:      &baselineReport,
		dexReaders:    ext.dexReaders,
		maxEntryBytes: ext.maxEntryBytes,
	})

	return buildInspectResult(ext.report, analysis), nil
}

// inspectResultToReport converts an InspectResult back to a report
// for internal use (baseline comparison, etc.).
func inspectResultToReport(ir *InspectResult) report {
	return report{
		Platform:              ir.Platform,
		Format:                ir.Format,
		Identity:              ir.Identity,
		Version:               ir.Version,
		Entry:                 ir.Entry,
		SDK:                   ir.SDK,
		Signing:               ir.Signing,
		Debuggable:            ir.Debuggable,
		AllowBackup:           ir.AllowBackup,
		UsesCleartextTraffic:  ir.UsesCleartextTraffic,
		NetworkSecurityConfig: ir.NetworkSecurityConfig,
		NSCPolicy:             ir.NSCPolicy,
		Permissions:           ir.Permissions,
		ExportedComponents:    ir.ExportedComponents,
		NetworkEndpoints:      ir.NetworkEndpoints,
		Diagnostics:           ir.Diagnostics,
	}
}

// Inspect performs a complete inspection from an [io.ReaderAt].
// This is useful when the package is already in memory or comes from
// a non-file source (e.g. an HTTP response body).
//
// The reader must contain a valid APK, XAPK, APKS, AAB, or IPA.
// It extracts metadata, runs security analysis, and returns a unified
// [InspectResult].
func Inspect(ctx context.Context, r io.ReaderAt, size int64) (*InspectResult, error) {
	ext, err := extractReportFromReader(ctx, r, size, InspectOptions{})
	if err != nil {
		return nil, err
	}

	analysis := analyzeReport(ext.report, analyzeOptions{
		dexReaders:    ext.dexReaders,
		maxEntryBytes: ext.maxEntryBytes,
	})

	return buildInspectResult(ext.report, analysis), nil
}

// buildInspectResult flattens a report and analysisResult into a single
// InspectResult struct.
func buildInspectResult(rpt report, analysis analysisResult) *InspectResult {
	return &InspectResult{
		Platform:              rpt.Platform,
		Format:                rpt.Format,
		Identity:              rpt.Identity,
		Version:               rpt.Version,
		Entry:                 rpt.Entry,
		SDK:                   rpt.SDK,
		Signing:               rpt.Signing,
		Icon:                  rpt.Icon,
		Debuggable:            rpt.Debuggable,
		AllowBackup:           rpt.AllowBackup,
		UsesCleartextTraffic:  rpt.UsesCleartextTraffic,
		NetworkSecurityConfig: rpt.NetworkSecurityConfig,
		NSCPolicy:             rpt.NSCPolicy,
		Permissions:           rpt.Permissions,
		ExportedComponents:    rpt.ExportedComponents,
		NetworkEndpoints:      analysis.report.NetworkEndpoints,
		Findings:              analysis.findings,
		SecretCandidates:      analysis.secretCandidates,
		Diff:                  analysis.diff,
		Diagnostics:           analysis.report.Diagnostics,
	}
}

// namedReader pairs a zip.Reader with a label identifying its origin
// (e.g. "" for top-level APK/AAB, "base.apk" for a nested split).
type namedReader struct {
	label  string // empty for top-level archive
	reader *zip.Reader
}

// extractionResult bundles the report with the ZIP reader and limits
// so callers can pass them to analyzeReport for DEX scanning.
type extractionResult struct {
	report        report
	zipReader     *zip.Reader   // top-level archive
	dexReaders    []namedReader // all archives containing DEX files (splits, modules)
	maxEntryBytes int64
}

// extractReportFromFile opens the file at the given path and extracts a
// [report]. The caller must close the returned [*os.File] after analysis
// is complete, because the ZIP reader in the returned [extractionResult]
// references the file handle.
func extractReportFromFile(ctx context.Context, path string, opts InspectOptions) (*os.File, extractionResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, extractionResult{}, err
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, extractionResult{}, err
	}

	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, extractionResult{}, err
	}

	limits := effectiveLimits(opts)
	if limits.MaxInputBytes > 0 && fi.Size() > limits.MaxInputBytes {
		_ = f.Close()
		return nil, extractionResult{}, wrapInspectError(ErrOversize)
	}

	ext, err := extractReportFromReader(ctx, f, fi.Size(), opts)
	if err != nil {
		_ = f.Close()
		return nil, extractionResult{}, err
	}

	return f, ext, nil
}

// extractReportFromReader extracts a [report] from the given [io.ReaderAt].
// All available sections are always extracted. This is the internal
// extraction function called by [extractReport] and [Inspect].
//
// The reader must contain a valid APK, XAPK, APKS, AAB, or IPA. The
// platform and format are automatically detected.
//
// This function follows a partial-success model: it returns as much data
// as it can, and records non-fatal problems in [report.Diagnostics].
// A non-nil error is returned only when the archive cannot be opened or
// the primary manifest is missing/unparseable.
func extractReportFromReader(ctx context.Context, r io.ReaderAt, size int64, opts InspectOptions) (extractionResult, error) {
	if err := ctx.Err(); err != nil {
		return extractionResult{}, err
	}

	zr, err := zip.NewReader(r, size)
	if err != nil {
		// zip.ErrFormat means it's simply not a ZIP file.
		// Other errors (truncated, I/O failures) indicate a corrupt archive.
		if errors.Is(err, zip.ErrFormat) {
			return extractionResult{}, &InspectError{
				Code:    "format.unsupported",
				Message: "file is not a valid ZIP archive",
				Err:     ErrUnsupportedFormat,
			}
		}
		return extractionResult{}, &InspectError{
			Code:    "archive.corrupt",
			Message: "ZIP archive is corrupt or unreadable",
			Err:     ErrArchiveCorrupt,
		}
	}

	limits := effectiveLimits(opts)

	if err := validateArchive(zr, size, limits, 0); err != nil {
		return extractionResult{}, wrapInspectError(err)
	}

	probe := probeZip(zr)

	sections := sectionAll
	iconOpts := iconOptions{}
	maxEntry := limits.MaxSingleEntryUncompressedBytes

	innerValidator := android.InnerArchiveValidator(func(inner *zip.Reader) error {
		return validateArchive(inner, 0, limits, 1)
	})

	var rpt report

	switch probe.Platform {
	case PlatformAndroid:
		switch probe.Format {
		case FormatXAPK:
			rpt, err = inspectXAPK(zr, sections, maxEntry, innerValidator)
		case FormatAPKS:
			rpt, err = inspectAPKS(zr, sections, maxEntry, innerValidator)
		case FormatAAB:
			rpt, err = inspectAAB(r, size, sections, iconOpts, maxEntry)
		default:
			rpt, err = inspectAndroid(zr, sections, r, size, maxEntry)
		}
	case PlatformIOS:
		rpt, err = inspectIOS(zr, sections, maxEntry)
	default:
		return extractionResult{}, &InspectError{
			Code:    "format.unsupported",
			Message: "unrecognized package format",
			Err:     ErrUnsupportedFormat,
		}
	}

	if err != nil {
		return extractionResult{}, wrapInspectError(err)
	}

	rpt.Format = probe.Format
	sortReport(&rpt)

	// Collect all zip.Readers that may contain DEX files.
	// For APK/AAB: the top-level archive itself.
	// For XAPK/APKS: every inner APK (base + splits + dynamic features).
	var dexReaders []namedReader
	if probe.Platform == PlatformAndroid {
		switch probe.Format {
		case FormatXAPK, FormatAPKS:
			named, splitDiags := android.OpenAllInnerAPKs(zr, maxEntry)
			for _, n := range named {
				if err := validateArchive(n.Reader, 0, limits, 1); err != nil {
					splitDiags = append(splitDiags, android.Diagnostic{
						Code:     "inner_apk.validation_failed",
						Severity: "warn",
						Message:  fmt.Sprintf("inner APK %s failed validation: %v", n.Name, err),
					})
					continue
				}
				dexReaders = append(dexReaders, namedReader{label: n.Name, reader: n.Reader})
			}
			for _, d := range splitDiags {
				rpt.Diagnostics = append(rpt.Diagnostics, Diagnostic{
					Code:     d.Code,
					Severity: Severity(d.Severity),
					Message:  d.Message,
				})
			}
		default:
			// APK and AAB: the top-level archive contains DEX directly.
			dexReaders = []namedReader{{reader: zr}}
		}
	}

	return extractionResult{
		report:        rpt,
		zipReader:     zr,
		dexReaders:    dexReaders,
		maxEntryBytes: maxEntry,
	}, nil
}

// buildAndroidReport converts an [android.Result] into a [report].
// This shared helper is used by all Android format inspectors.
func buildAndroidReport(result *android.Result, diags []android.Diagnostic, sections section) report {
	rpt := report{
		Platform: PlatformAndroid,
	}

	if sections&sectionIdentity != 0 {
		rpt.Identity = Identity{
			Identifier:  result.PackageName,
			DisplayName: result.Label,
		}
	}

	if sections&sectionVersion != 0 {
		rpt.Version = Version{
			Marketing: result.VersionName,
			Build:     result.VersionCode,
		}
	}

	if sections&sectionEntryPoint != 0 {
		rpt.Entry = EntryPoint{
			Kind: "activity",
			Name: result.MainActivity,
		}
	}

	if sections&sectionPermissions != 0 {
		for _, p := range result.Permissions {
			rpt.Permissions = append(rpt.Permissions, Permission{
				Canonical: canonicalPermission(p),
				RawName:   p,
				Source:    "manifest",
			})
		}
	}

	rpt.Debuggable = result.Debuggable
	rpt.AllowBackup = result.AllowBackup
	rpt.UsesCleartextTraffic = result.UsesCleartextTraffic
	rpt.NetworkSecurityConfig = result.NetworkSecurityConfig
	if result.NSCPolicy != nil {
		rpt.NSCPolicy = &NetworkSecurityPolicy{
			CleartextPermitted: result.NSCPolicy.CleartextPermitted,
			HasPinSet:          result.NSCPolicy.HasPinSet,
			TrustAnchors:       result.NSCPolicy.TrustAnchors,
		}
		for _, dc := range result.NSCPolicy.DomainConfigs {
			rpt.NSCPolicy.DomainConfigs = append(rpt.NSCPolicy.DomainConfigs, DomainConfig{
				Domains:            dc.Domains,
				CleartextPermitted: dc.CleartextPermitted,
				HasPinSet:          dc.HasPinSet,
			})
		}
	}

	for _, ec := range result.ExportedComponents {
		comp := ExportedComponent{
			Kind:        ec.Kind,
			Name:        ec.Name,
			Exported:    ec.Exported,
			Permission:  ec.Permission,
			Authorities: ec.Authorities,
		}
		for _, f := range ec.IntentFilters {
			filter := IntentFilter{
				Actions:    f.Actions,
				Categories: f.Categories,
			}
			for _, d := range f.DataSpecs {
				filter.Data = append(filter.Data, DataSpec{
					Scheme: d.Scheme,
					Host:   d.Host,
					Path:   d.Path,
				})
			}
			comp.IntentFilters = append(comp.IntentFilters, filter)
		}
		rpt.ExportedComponents = append(rpt.ExportedComponents, comp)
	}

	if sections&sectionIcon != 0 && len(result.IconBytes) > 0 {
		rpt.Icon = &IconAsset{
			Path:   result.IconPath,
			Bytes:  result.IconBytes,
			Format: result.IconFormat,
			Width:  result.IconWidth,
			Height: result.IconHeight,
		}
	}

	if sections&sectionSDK != 0 {
		rpt.SDK = SDKConstraints{
			MinSDK:    result.MinSDK,
			TargetSDK: result.TargetSDK,
		}
	}

	if sections&sectionSigning != 0 && result.Signing != nil {
		si := &SigningInfo{Scheme: result.Signing.Scheme}
		for _, c := range result.Signing.Certs {
			si.Certificates = append(si.Certificates, CertSummary{
				Subject:           c.Subject,
				Issuer:            c.Issuer,
				NotBefore:         c.NotBefore,
				NotAfter:          c.NotAfter,
				SHA256Fingerprint: c.SHA256Fingerprint,
				SerialNumber:      c.SerialNumber,
			})
		}
		rpt.Signing = si
	}

	if sections&sectionPlatformRaw != 0 {
		rpt.PlatformData = &androidReport{RawManifest: result.RawManifest}
	}

	for _, d := range diags {
		rpt.Diagnostics = append(rpt.Diagnostics, Diagnostic{
			Code:     d.Code,
			Severity: Severity(d.Severity),
			Message:  d.Message,
		})
	}

	return rpt
}

// inspectAndroid delegates to the Android APK adapter.
func inspectAndroid(zr *zip.Reader, sections section, r io.ReaderAt, size int64, maxEntryBytes int64) (report, error) {
	result, diags, err := android.Inspect(zr, uint64(sections), r, size, maxEntryBytes)
	if err != nil {
		return report{}, err
	}
	return buildAndroidReport(result, diags, sections), nil
}

// inspectXAPK delegates to the Android XAPK adapter.
func inspectXAPK(zr *zip.Reader, sections section, maxEntryBytes int64, validate android.InnerArchiveValidator) (report, error) {
	result, diags, err := android.InspectXAPK(zr, uint64(sections), maxEntryBytes, validate)
	if err != nil {
		return report{}, err
	}
	return buildAndroidReport(result, diags, sections), nil
}

// inspectAPKS delegates to the Android APKS adapter.
func inspectAPKS(zr *zip.Reader, sections section, maxEntryBytes int64, validate android.InnerArchiveValidator) (report, error) {
	result, diags, err := android.InspectAPKS(zr, uint64(sections), maxEntryBytes, validate)
	if err != nil {
		return report{}, err
	}
	return buildAndroidReport(result, diags, sections), nil
}

// inspectAAB delegates to the Android AAB adapter.
func inspectAAB(r io.ReaderAt, size int64, sections section, iconOpts iconOptions, maxEntryBytes int64) (report, error) {
	result, diags, err := android.InspectAAB(r, size, uint64(sections), iconOpts.sizePx, maxEntryBytes)
	if err != nil {
		return report{}, err
	}
	return buildAndroidReport(result, diags, sections), nil
}

// inspectIOS delegates to the iOS adapter and normalizes the result.
func inspectIOS(zr *zip.Reader, sections section, maxEntryBytes int64) (report, error) {
	result, diags, err := ios.Inspect(zr, uint64(sections), maxEntryBytes)
	if err != nil {
		return report{}, err
	}

	rpt := report{
		Platform: PlatformIOS,
	}

	if sections&sectionIdentity != 0 {
		rpt.Identity = Identity{
			Identifier:  result.BundleID,
			DisplayName: result.DisplayName,
		}
	}

	if sections&sectionVersion != 0 {
		rpt.Version = Version{
			Marketing: result.ShortVersion,
			Build:     result.BundleVersion,
		}
	}

	if sections&sectionEntryPoint != 0 {
		rpt.Entry = EntryPoint{
			Kind: "executable",
			Name: result.Executable,
		}
	}

	if sections&sectionPermissions != 0 {
		for _, p := range result.Permissions {
			rpt.Permissions = append(rpt.Permissions, Permission{
				Canonical: canonicalIOSPermission(p.RawName),
				RawName:   p.RawName,
				Source:    p.Source,
			})
		}
	}

	if sections&sectionIcon != 0 && len(result.IconBytes) > 0 {
		rpt.Icon = &IconAsset{
			Path:   result.IconPath,
			Bytes:  result.IconBytes,
			Format: result.IconFormat,
			Width:  result.IconWidth,
			Height: result.IconHeight,
		}
	}

	if sections&sectionSDK != 0 {
		rpt.SDK = SDKConstraints{
			MinSDK: result.MinimumOSVersion,
		}
	}

	if sections&sectionSigning != 0 && result.Signing != nil {
		si := &SigningInfo{Scheme: "apple"}
		for _, c := range result.Signing.Certs {
			si.Certificates = append(si.Certificates, CertSummary{
				Subject:           c.Subject,
				Issuer:            c.Issuer,
				NotBefore:         c.NotBefore,
				NotAfter:          c.NotAfter,
				SHA256Fingerprint: c.SHA256Fingerprint,
				SerialNumber:      c.SerialNumber,
			})
		}
		rpt.Signing = si
	}

	if sections&sectionPlatformRaw != 0 {
		rpt.PlatformData = &iosReport{
			InfoPlist:    result.InfoPlist,
			Entitlements: result.Entitlements,
		}
	}

	// Extract network endpoints from plist and entitlements.
	if result.InfoPlist != nil {
		rpt.NetworkEndpoints = append(rpt.NetworkEndpoints, extractEndpointsFromPlist(result.InfoPlist)...)
	}
	if result.Entitlements != nil {
		rpt.NetworkEndpoints = append(rpt.NetworkEndpoints, extractEndpointsFromEntitlements(result.Entitlements)...)
	}

	for _, d := range diags {
		rpt.Diagnostics = append(rpt.Diagnostics, Diagnostic{
			Code:     d.Code,
			Severity: Severity(d.Severity),
			Message:  d.Message,
		})
	}

	return rpt, nil
}

// sortReport sorts the variable-length slices in a report for stable output.
func sortReport(r *report) {
	sort.Slice(r.Permissions, func(i, j int) bool {
		return r.Permissions[i].RawName < r.Permissions[j].RawName
	})
	sort.Slice(r.ExportedComponents, func(i, j int) bool {
		if r.ExportedComponents[i].Kind != r.ExportedComponents[j].Kind {
			return r.ExportedComponents[i].Kind < r.ExportedComponents[j].Kind
		}
		return r.ExportedComponents[i].Name < r.ExportedComponents[j].Name
	})
	sort.Slice(r.NetworkEndpoints, func(i, j int) bool {
		return r.NetworkEndpoints[i].Host < r.NetworkEndpoints[j].Host
	})
	sort.Slice(r.Diagnostics, func(i, j int) bool {
		return r.Diagnostics[i].Code < r.Diagnostics[j].Code
	})
}
