package mobilepkg

// Platform represents the mobile platform of an application package.
type Platform string

const (
	// PlatformUnknown indicates an unrecognized package format.
	PlatformUnknown Platform = "unknown"
	// PlatformAndroid indicates an Android APK package.
	PlatformAndroid Platform = "android"
	// PlatformIOS indicates an iOS IPA package.
	PlatformIOS Platform = "ios"
)

// Format identifies the specific packaging format of a mobile application.
// While [Platform] tells you Android vs iOS, Format distinguishes the
// concrete archive layout (e.g. APK vs XAPK vs AAB).
type Format string

const (
	// FormatUnknown indicates an unrecognized format.
	FormatUnknown Format = "unknown"
	// FormatAPK indicates a standard Android APK.
	FormatAPK Format = "apk"
	// FormatIPA indicates an iOS IPA.
	FormatIPA Format = "ipa"
	// FormatXAPK indicates an XAPK (APKPure extended package with
	// manifest.json and one or more inner APKs).
	FormatXAPK Format = "xapk"
	// FormatAPKS indicates an APK Set archive produced by bundletool,
	// containing split APKs under a splits/ directory.
	FormatAPKS Format = "apks"
	// FormatAAB indicates an Android App Bundle whose manifest is
	// encoded in protobuf format.
	FormatAAB Format = "aab"
)

// Section is a bitmask that selects which parts of a [Report] to populate.
// Callers combine sections with bitwise OR to request only the data they need.
type Section uint64

const (
	// SectionIdentity requests package identifier and display name.
	SectionIdentity Section = 1 << iota
	// SectionVersion requests marketing and build version strings.
	SectionVersion
	// SectionEntryPoint requests the main entry point (activity or executable).
	SectionEntryPoint
	// SectionPermissions requests the list of declared permissions.
	SectionPermissions
	// SectionIcon requests icon asset extraction.
	SectionIcon
	// SectionPlatformRaw requests the platform-specific raw data
	// (AndroidReport or IOSReport).
	SectionPlatformRaw
	// SectionSDK requests SDK and OS version constraints
	// (e.g. minSdkVersion, targetSdkVersion, MinimumOSVersion).
	SectionSDK
	// SectionSigning requests code signing and certificate information.
	SectionSigning

	// SectionAll is a convenience mask that selects every section.
	SectionAll = SectionIdentity | SectionVersion | SectionEntryPoint |
		SectionPermissions | SectionIcon | SectionPlatformRaw | SectionSDK |
		SectionSigning
)

// ProbeResult holds the lightweight detection result returned by [ProbeFile].
type ProbeResult struct {
	// Platform is the detected mobile platform.
	Platform Platform
	// Format identifies the specific packaging format (e.g. "apk", "xapk", "aab").
	Format Format
	// Container describes the archive format (e.g. "zip").
	Container string
	// Hints provides human-readable clues about what was detected
	// (e.g. "has AndroidManifest.xml", "has Info.plist").
	Hints []string
}

// InspectOptions controls what [InspectFile] extracts from a package.
type InspectOptions struct {
	// Sections selects which parts of the Report to populate.
	// Zero value means SectionAll.
	Sections Section
	// IconOptions controls icon extraction behavior.
	Icon IconOptions
}

// IconOptions configures how icons are extracted during inspection.
type IconOptions struct {
	// SizePx requests an icon closest to this size in pixels.
	// Zero means the best available candidate.
	//
	// Currently only effective for AAB files, where it selects the
	// resource density closest to the given pixel size. For APK, XAPK,
	// APKS, and IPA files, the best available icon is always returned
	// regardless of this setting.
	SizePx int
}

// Report is the unified inspection result for a mobile application package.
type Report struct {
	// Platform is the detected platform.
	Platform Platform
	// Format identifies the specific packaging format (e.g. "apk", "xapk", "aab").
	Format Format
	// Identity holds the package identifier and display name.
	Identity Identity
	// Version holds the marketing and build version strings.
	Version Version
	// Entry holds the main entry point of the application.
	Entry EntryPoint
	// Permissions lists the declared permissions.
	Permissions []Permission
	// SDK holds the SDK and OS version constraints, if requested.
	SDK SDKConstraints
	// Signing holds code signing and certificate information, if requested.
	// Nil when signing information is not requested or not available.
	Signing *SigningInfo
	// Icon holds the extracted icon asset, if requested.
	Icon *IconAsset
	// PlatformData carries the platform-specific raw report.
	// Use [AsAndroid] or [AsIOS] to access the typed value.
	PlatformData any
	// Diagnostics collects non-fatal issues encountered during inspection.
	Diagnostics []Diagnostic
}

// SigningInfo holds code signing and certificate information extracted
// from a mobile application package.
type SigningInfo struct {
	// Scheme describes the signing schemes detected.
	// Android examples: "v1", "v2", "v3", "v1+v2", "v1+v3".
	// iOS: "apple".
	Scheme string
	// Certificates lists the signing certificates found.
	Certificates []CertSummary
}

// CertSummary holds a summary of an X.509 certificate used for code signing.
type CertSummary struct {
	// Subject is the certificate subject (typically CN or O).
	Subject string
	// Issuer is the certificate issuer.
	Issuer string
	// NotBefore is the certificate validity start in RFC 3339 format.
	NotBefore string
	// NotAfter is the certificate validity end in RFC 3339 format.
	NotAfter string
	// SHA256Fingerprint is the hex-encoded SHA-256 fingerprint of the DER certificate.
	SHA256Fingerprint string
	// SerialNumber is the certificate serial number in decimal.
	SerialNumber string
}

// SDKConstraints holds the SDK and OS version requirements extracted
// from the application manifest.
type SDKConstraints struct {
	// MinSDK is the minimum SDK/OS version required.
	// Android: minSdkVersion (e.g. "21"). iOS: MinimumOSVersion (e.g. "15.0").
	MinSDK string
	// TargetSDK is the target SDK version (Android only).
	// Empty for iOS packages.
	TargetSDK string
}

// Identity holds the package identifier and display name.
type Identity struct {
	// Identifier is the package name (Android) or bundle ID (iOS).
	Identifier string
	// DisplayName is the user-visible application name.
	DisplayName string
}

// Version holds marketing and build version strings.
type Version struct {
	// Marketing is the user-facing version string
	// (Android versionName / iOS CFBundleShortVersionString).
	Marketing string
	// Build is the internal build identifier
	// (Android versionCode / iOS CFBundleVersion).
	Build string
}

// EntryPoint describes the main entry point of the application.
type EntryPoint struct {
	// Kind classifies the entry point ("activity", "executable", or "unknown").
	Kind string
	// Name is the fully qualified name of the entry point.
	Name string
}

// Permission represents a declared permission in a mobile application package.
type Permission struct {
	// Canonical is a cross-platform classification (e.g. "camera", "location").
	// Empty if no mapping is available.
	Canonical string
	// RawName is the platform-specific permission identifier
	// (e.g. "android.permission.CAMERA", "NSCameraUsageDescription").
	RawName string
	// Source indicates where the permission was declared
	// ("manifest", "info_plist", or "entitlement").
	Source string
}

// IconAsset holds the extracted icon data.
type IconAsset struct {
	// Path is the archive-internal path of the icon file.
	Path string
	// Bytes contains the raw icon data.
	Bytes []byte
	// Format describes the image format (e.g. "png", "jpeg").
	Format string
	// Width is the icon width in pixels (0 if unknown).
	Width int
	// Height is the icon height in pixels (0 if unknown).
	Height int
}

// AndroidReport carries Android-specific data from an APK inspection.
type AndroidReport struct {
	// RawManifest holds the parsed AndroidManifest fields.
	RawManifest map[string]any
}

// IOSReport carries iOS-specific data from an IPA inspection.
type IOSReport struct {
	// InfoPlist holds the parsed Info.plist dictionary.
	InfoPlist map[string]any
	// Entitlements holds the parsed entitlements dictionary.
	Entitlements map[string]any
}

// AsAndroid extracts the [AndroidReport] from a [Report].
// It returns nil and false if the report is not for Android.
func AsAndroid(report Report) (*AndroidReport, bool) {
	r, ok := report.PlatformData.(*AndroidReport)
	return r, ok
}

// AsIOS extracts the [IOSReport] from a [Report].
// It returns nil and false if the report is not for iOS.
func AsIOS(report Report) (*IOSReport, bool) {
	r, ok := report.PlatformData.(*IOSReport)
	return r, ok
}

// Diff represents the structured differences between two [Report] values.
type Diff struct {
	// OldPlatform is the platform of the old report.
	OldPlatform Platform
	// NewPlatform is the platform of the new report.
	NewPlatform Platform
	// IdentityChanged is true when the identity fields differ.
	IdentityChanged bool
	// VersionChanged is true when the version fields differ.
	VersionChanged bool
	// EntryChanged is true when the entry point fields differ.
	EntryChanged bool
	// AddedPermissions lists permissions present in the new report but not the old.
	AddedPermissions []Permission
	// RemovedPermissions lists permissions present in the old report but not the new.
	RemovedPermissions []Permission
}
