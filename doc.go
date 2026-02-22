// Package mobilepkg provides a unified API for inspecting Android (APK) and
// iOS (IPA) mobile application packages.
//
// It abstracts platform-specific differences so that callers can perform common
// operational tasks with a single set of API calls:
//
//   - CI quality gates: validate identity, version, and permissions
//   - Catalog extraction: collect display name, icon, and platform info
//   - Security audits: enumerate permissions and entitlements
//   - Release diff: compare two packages to detect changes
//
// The public surface consists of three layers:
//
//  1. [ProbeFile] — cheap file-type detection (APK vs IPA)
//  2. [InspectFile] — rich, section-selectable report extraction
//  3. [DiffReports] — structured comparison of two [Report] values
//
// # Example
//
//	result, err := mobilepkg.ProbeFile("app-release.apk")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(result.Platform) // "android"
//
//	report, err := mobilepkg.InspectFile(ctx, "app-release.apk", mobilepkg.InspectOptions{
//	    Sections: mobilepkg.SectionIdentity | mobilepkg.SectionVersion,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(report.Identity.Identifier) // "com.example.app"
package mobilepkg
