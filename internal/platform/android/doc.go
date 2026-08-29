// Package android provides Android-specific APK inspection logic.
// It parses AndroidManifest.xml and resources.arsc from the ZIP archive
// and normalizes the extracted data into the mobilepkg report model.
package android

// The manifest attribute names this package reads, and the one severity it
// reports. Naming them keeps the diagnostics map keys in aab.go, inspect.go and
// xapk.go spelled identically -- they are consumed by key, so a typo in one
// path would produce a silently missing field rather than a compile error.
const (
	attrPackage     = "package"
	attrVersionCode = "versionCode"
	attrVersionName = "versionName"

	// sevWarn is the severity every diagnostic in this package reports.
	sevWarn = "warn"
)
