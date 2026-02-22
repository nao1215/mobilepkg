// Package mobilepkg provides a unified API for inspecting and analyzing
// Android (APK/XAPK/APKS/AAB) and iOS (IPA) mobile application packages.
//
// It abstracts platform-specific differences so that callers can perform
// common operational tasks with a single set of API calls:
//
//   - CI quality gates: validate identity, version, and permissions
//   - Security inspection: detect debuggable builds, exposed components, dangerous permissions
//   - Release diff: compare two packages to detect changes
//   - Catalog extraction: collect display name, icon, and platform info
//
// The primary entry point is [InspectFile], which performs a complete
// inspection in a single call — extracting package metadata, running
// analysis, and returning a unified [InspectResult]:
//
//	result, err := mobilepkg.InspectFile(ctx, "app.apk")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(result.Identity.Identifier) // "com.example.app"
//	for _, f := range result.Findings {
//	    fmt.Printf("[%s] %s\n", f.Severity, f.Message)
//	}
//
// For CI fail conditions, use [Check]:
//
//	verdict := mobilepkg.Check(result, mobilepkg.DefaultFailPolicy())
//
// For release comparison, use [Compare]:
//
//	diff := mobilepkg.Compare(oldResult, newResult)
//
// For custom validation rules, use [Validate]:
//
//	violations := mobilepkg.Validate(result, rules)
//
// For expert use, [InspectFileWithOptions] accepts archive safety limits.
package mobilepkg
