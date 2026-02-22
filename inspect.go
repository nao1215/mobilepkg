package mobilepkg

import (
	"archive/zip"
	"context"
	"errors"
	"io"
	"os"
	"sort"

	"github.com/nao1215/mobilepkg/internal/platform/android"
	"github.com/nao1215/mobilepkg/internal/platform/ios"
)

// Inspect extracts a [Report] from the given [io.ReaderAt] according to the
// requested sections in opts. This is useful when the package is already in
// memory or comes from a non-file source (e.g. an HTTP response body).
//
// The reader must contain a valid APK, XAPK, APKS, AAB, or IPA. The
// platform and format are automatically detected.
//
// Inspect follows a partial-success model: it returns as much data as it
// can, and records non-fatal problems in [Report.Diagnostics]. A non-nil
// error is returned only when the archive cannot be opened or the primary
// manifest is missing/unparseable.
func Inspect(ctx context.Context, r io.ReaderAt, size int64, opts InspectOptions) (Report, error) {
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}

	zr, err := zip.NewReader(r, size)
	if err != nil {
		// zip.ErrFormat means it's simply not a ZIP file.
		// Other errors (truncated, I/O failures) indicate a corrupt archive.
		if errors.Is(err, zip.ErrFormat) {
			return Report{}, &InspectError{
				Code:    "format.unsupported",
				Message: "file is not a valid ZIP archive",
				Err:     ErrUnsupportedFormat,
			}
		}
		return Report{}, &InspectError{
			Code:    "archive.corrupt",
			Message: "ZIP archive is corrupt or unreadable",
			Err:     ErrArchiveCorrupt,
		}
	}

	probe := probeZip(zr)

	sections := opts.Sections
	if sections == 0 {
		sections = SectionAll
	}

	// If icon extraction is not requested, clear any icon options to avoid
	// unnecessary work in adapters.
	iconOpts := opts.Icon
	if sections&SectionIcon == 0 {
		iconOpts = IconOptions{}
	}

	var report Report

	switch probe.Platform {
	case PlatformAndroid:
		switch probe.Format {
		case FormatXAPK:
			report, err = inspectXAPK(zr, sections)
		case FormatAPKS:
			report, err = inspectAPKS(zr, sections)
		case FormatAAB:
			report, err = inspectAAB(r, size, sections, iconOpts)
		default:
			report, err = inspectAndroid(zr, sections, r, size)
		}
	case PlatformIOS:
		report, err = inspectIOS(zr, sections)
	default:
		return Report{}, &InspectError{
			Code:    "format.unsupported",
			Message: "unrecognized package format",
			Err:     ErrUnsupportedFormat,
		}
	}

	if err != nil {
		return Report{}, wrapInspectError(err)
	}

	report.Format = probe.Format
	sortReport(&report)
	return report, nil
}

// InspectFile opens the file at the given path and extracts a [Report]
// according to the requested sections in opts.
//
// The file must be a valid APK, XAPK, APKS, AAB, or IPA. The platform
// and format are automatically detected (equivalent to calling [ProbeFile]
// internally).
//
// InspectFile follows a partial-success model: it returns as much data
// as it can, and records non-fatal problems in [Report.Diagnostics].
// A non-nil error is returned only when the archive cannot be opened or
// the primary manifest is missing/unparseable.
func InspectFile(ctx context.Context, path string, opts InspectOptions) (Report, error) {
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}

	f, err := os.Open(path)
	if err != nil {
		return Report{}, err
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return Report{}, err
	}

	return Inspect(ctx, f, fi.Size(), opts)
}

// buildAndroidReport converts an [android.Result] into a [Report].
// This shared helper is used by all Android format inspectors.
func buildAndroidReport(result *android.Result, diags []android.Diagnostic, sections Section) Report {
	report := Report{
		Platform: PlatformAndroid,
	}

	if sections&SectionIdentity != 0 {
		report.Identity = Identity{
			Identifier:  result.PackageName,
			DisplayName: result.Label,
		}
	}

	if sections&SectionVersion != 0 {
		report.Version = Version{
			Marketing: result.VersionName,
			Build:     result.VersionCode,
		}
	}

	if sections&SectionEntryPoint != 0 {
		report.Entry = EntryPoint{
			Kind: "activity",
			Name: result.MainActivity,
		}
	}

	if sections&SectionPermissions != 0 {
		for _, p := range result.Permissions {
			report.Permissions = append(report.Permissions, Permission{
				Canonical: canonicalPermission(p),
				RawName:   p,
				Source:    "manifest",
			})
		}
	}

	if sections&SectionIcon != 0 && len(result.IconBytes) > 0 {
		report.Icon = &IconAsset{
			Path:   result.IconPath,
			Bytes:  result.IconBytes,
			Format: result.IconFormat,
			Width:  result.IconWidth,
			Height: result.IconHeight,
		}
	}

	if sections&SectionSDK != 0 {
		report.SDK = SDKConstraints{
			MinSDK:    result.MinSDK,
			TargetSDK: result.TargetSDK,
		}
	}

	if sections&SectionSigning != 0 && result.Signing != nil {
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
		report.Signing = si
	}

	if sections&SectionPlatformRaw != 0 {
		report.PlatformData = &AndroidReport{
			RawManifest: result.RawManifest,
		}
	}

	for _, d := range diags {
		report.Diagnostics = append(report.Diagnostics, Diagnostic{
			Code:     d.Code,
			Severity: Severity(d.Severity),
			Message:  d.Message,
		})
	}

	return report
}

// inspectAndroid delegates to the Android APK adapter.
func inspectAndroid(zr *zip.Reader, sections Section, r io.ReaderAt, size int64) (Report, error) {
	result, diags, err := android.Inspect(zr, uint64(sections), r, size)
	if err != nil {
		return Report{}, err
	}
	return buildAndroidReport(result, diags, sections), nil
}

// inspectXAPK delegates to the Android XAPK adapter.
func inspectXAPK(zr *zip.Reader, sections Section) (Report, error) {
	result, diags, err := android.InspectXAPK(zr, uint64(sections))
	if err != nil {
		return Report{}, err
	}
	return buildAndroidReport(result, diags, sections), nil
}

// inspectAPKS delegates to the Android APKS adapter.
func inspectAPKS(zr *zip.Reader, sections Section) (Report, error) {
	result, diags, err := android.InspectAPKS(zr, uint64(sections))
	if err != nil {
		return Report{}, err
	}
	return buildAndroidReport(result, diags, sections), nil
}

// inspectAAB delegates to the Android AAB adapter.
func inspectAAB(r io.ReaderAt, size int64, sections Section, iconOpts IconOptions) (Report, error) {
	result, diags, err := android.InspectAAB(r, size, uint64(sections), iconOpts.SizePx)
	if err != nil {
		return Report{}, err
	}
	return buildAndroidReport(result, diags, sections), nil
}

// inspectIOS delegates to the iOS adapter and normalizes the result.
func inspectIOS(zr *zip.Reader, sections Section) (Report, error) {
	result, diags, err := ios.Inspect(zr, uint64(sections))
	if err != nil {
		return Report{}, err
	}

	report := Report{
		Platform: PlatformIOS,
	}

	if sections&SectionIdentity != 0 {
		report.Identity = Identity{
			Identifier:  result.BundleID,
			DisplayName: result.DisplayName,
		}
	}

	if sections&SectionVersion != 0 {
		report.Version = Version{
			Marketing: result.ShortVersion,
			Build:     result.BundleVersion,
		}
	}

	if sections&SectionEntryPoint != 0 {
		report.Entry = EntryPoint{
			Kind: "executable",
			Name: result.Executable,
		}
	}

	if sections&SectionPermissions != 0 {
		for _, p := range result.Permissions {
			report.Permissions = append(report.Permissions, Permission{
				Canonical: canonicalIOSPermission(p.RawName),
				RawName:   p.RawName,
				Source:    p.Source,
			})
		}
	}

	if sections&SectionIcon != 0 && len(result.IconBytes) > 0 {
		report.Icon = &IconAsset{
			Path:   result.IconPath,
			Bytes:  result.IconBytes,
			Format: result.IconFormat,
			Width:  result.IconWidth,
			Height: result.IconHeight,
		}
	}

	if sections&SectionSDK != 0 {
		report.SDK = SDKConstraints{
			MinSDK: result.MinimumOSVersion,
		}
	}

	if sections&SectionSigning != 0 && result.Signing != nil {
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
		report.Signing = si
	}

	if sections&SectionPlatformRaw != 0 {
		report.PlatformData = &IOSReport{
			InfoPlist:    result.InfoPlist,
			Entitlements: result.Entitlements,
		}
	}

	for _, d := range diags {
		report.Diagnostics = append(report.Diagnostics, Diagnostic{
			Code:     d.Code,
			Severity: Severity(d.Severity),
			Message:  d.Message,
		})
	}

	return report, nil
}

// sortReport sorts the variable-length slices in a Report for stable output.
func sortReport(r *Report) {
	sort.Slice(r.Permissions, func(i, j int) bool {
		return r.Permissions[i].RawName < r.Permissions[j].RawName
	})
	sort.Slice(r.Diagnostics, func(i, j int) bool {
		return r.Diagnostics[i].Code < r.Diagnostics[j].Code
	})
}
