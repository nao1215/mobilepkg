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

// section is an internal bitmask that selects which parts of a [report]
// to populate. The public API always extracts all sections; this type
// exists only for internal routing to platform adapters.
type section uint64

const (
	sectionIdentity section = 1 << iota
	sectionVersion
	sectionEntryPoint
	sectionPermissions
	sectionIcon
	sectionPlatformRaw
	sectionSDK
	sectionSigning

	sectionAll = sectionIdentity | sectionVersion | sectionEntryPoint |
		sectionPermissions | sectionIcon | sectionPlatformRaw | sectionSDK |
		sectionSigning
)

// ArchiveLimits controls safety limits applied when reading ZIP archives.
// These limits protect against malicious or malformed archives such as
// zip bombs, path-traversal attacks, and symlink exploits.
//
// A zero value for any numeric field means "no limit" for that check.
// Use [DefaultArchiveLimits] to obtain a set of sensible defaults.
type ArchiveLimits struct {
	// MaxInputBytes is the maximum allowed size of the input file in bytes.
	// Archives larger than this are rejected before parsing.
	MaxInputBytes int64
	// MaxEntryCount is the maximum number of entries allowed in the archive.
	MaxEntryCount int
	// MaxTotalUncompressedBytes is the maximum total uncompressed size
	// of all entries combined.
	MaxTotalUncompressedBytes int64
	// MaxSingleEntryUncompressedBytes is the maximum uncompressed size
	// of any single entry.
	MaxSingleEntryUncompressedBytes int64
	// MaxNestingDepth is the maximum allowed depth for nested archives
	// (e.g. an APK inside an XAPK). Zero means no limit on nesting depth.
	MaxNestingDepth int
	// MaxPathLength is the maximum allowed length (in bytes) for any
	// single entry path within the archive.
	MaxPathLength int
	// MaxCompressionRatio is the maximum allowed ratio of uncompressed
	// to compressed size for any single entry. This guards against
	// compression bombs. Zero means no ratio limit.
	MaxCompressionRatio float64
	// AllowSymlinks controls whether symlink entries in the archive are
	// accepted. When false (the default), symlinks cause a safety error.
	AllowSymlinks bool
}

// DefaultArchiveLimits returns an [ArchiveLimits] with sensible defaults
// suitable for most use cases.
//
//   - MaxInputBytes:                   2 GiB
//   - MaxEntryCount:                   100,000
//   - MaxTotalUncompressedBytes:       4 GiB
//   - MaxSingleEntryUncompressedBytes: 512 MiB
//   - MaxNestingDepth:                 4
//   - MaxPathLength:                   512
//   - MaxCompressionRatio:             100
//   - AllowSymlinks:                   false
func DefaultArchiveLimits() ArchiveLimits {
	return ArchiveLimits{
		MaxInputBytes:                   2 << 30, // 2 GiB
		MaxEntryCount:                   100_000,
		MaxTotalUncompressedBytes:       4 << 30,   // 4 GiB
		MaxSingleEntryUncompressedBytes: 512 << 20, // 512 MiB
		MaxNestingDepth:                 4,
		MaxPathLength:                   512,
		MaxCompressionRatio:             100,
		AllowSymlinks:                   false,
	}
}

// InspectOptions controls what [InspectFileWithOptions] extracts from a package.
// All sections are always extracted; the options control archive safety
// limits. Icons are always extracted at the best available size.
type InspectOptions struct {
	// Archive controls safety limits for archive processing.
	// Nil means [DefaultArchiveLimits] are used.
	Archive *ArchiveLimits
}

// iconOptions configures how icons are extracted during inspection.
// This is an internal type; icons are always extracted at default size
// in the public API.
type iconOptions struct {
	// sizePx requests an icon closest to this size in pixels.
	// Zero means the best available candidate.
	//
	// Currently only effective for AAB files, where it selects the
	// resource density closest to the given pixel size. For APK, XAPK,
	// APKS, and IPA files, the best available icon is always returned
	// regardless of this setting.
	sizePx int
}

// report is the low-level inspection result for a mobile application package.
// It contains only the extracted facts — identity, version, permissions,
// signing, and other data read directly from the archive. This type is
// internal; most callers should use [InspectFile], which returns the
// higher-level [InspectResult] that includes both extracted facts and
// security analysis findings.
type report struct {
	// Platform is the detected platform.
	Platform Platform `json:"platform"`
	// Format identifies the specific packaging format (e.g. "apk", "xapk", "aab").
	Format Format `json:"format"`
	// Identity holds the package identifier and display name.
	Identity Identity `json:"identity"`
	// Version holds the marketing and build version strings.
	Version Version `json:"version"`
	// Entry holds the main entry point of the application.
	Entry EntryPoint `json:"entry"`
	// Permissions lists the declared permissions.
	Permissions []Permission `json:"permissions"`
	// SDK holds the SDK and OS version constraints, if requested.
	SDK SDKConstraints `json:"sdk"`
	// Signing holds code signing and certificate information, if requested.
	// Nil when signing information is not requested or not available.
	Signing *SigningInfo `json:"signing,omitempty"`
	// Icon holds the extracted icon asset, if requested.
	Icon *IconAsset `json:"icon,omitempty"`
	// Debuggable indicates whether the application is marked as debuggable.
	// True for debug builds — a serious security issue in production.
	Debuggable bool `json:"debuggable"`
	// AllowBackup indicates whether the application allows data backup.
	// True by default on Android, which may expose user data.
	AllowBackup bool `json:"allow_backup"`
	// UsesCleartextTraffic indicates whether the application allows
	// cleartext (unencrypted HTTP) network traffic.
	UsesCleartextTraffic bool `json:"uses_cleartext_traffic"`
	// NetworkSecurityConfig is the resource reference to the network
	// security configuration (Android only, e.g. "@xml/network_security_config").
	// Empty when not declared or for iOS packages.
	NetworkSecurityConfig string `json:"network_security_config,omitempty"`
	// NSCPolicy holds the parsed network security configuration.
	// Nil when no network_security_config.xml is found or for iOS packages.
	NSCPolicy *NetworkSecurityPolicy `json:"nsc_policy,omitempty"`
	// ExportedComponents lists components (activities, services, receivers,
	// providers) that are exported and accessible to other applications.
	ExportedComponents []ExportedComponent `json:"exported_components"`
	// NetworkEndpoints lists network endpoints found in the package metadata.
	NetworkEndpoints []NetworkEndpoint `json:"network_endpoints"`
	// PlatformData carries the platform-specific raw report.
	// Excluded from JSON serialization; use typed accessors instead.
	PlatformData any `json:"-"`
	// Diagnostics collects non-fatal issues encountered during inspection.
	Diagnostics []Diagnostic `json:"diagnostics"`
}

// analysisResult holds the output of [analyzeReport]. It pairs the
// original inspection [Report] with security findings, secret candidates,
// and an optional baseline diff. This type is used internally by
// [InspectFile] to build the final [InspectResult].
type analysisResult struct {
	// report is the underlying inspection result.
	report report
	// findings holds security-relevant observations.
	findings []Finding
	// secretCandidates lists potential secrets, tokens, or credentials.
	secretCandidates []SecretCandidate
	// diff holds the comparison against a baseline, if provided.
	diff *Diff
}

// analyzeOptions controls how [analyzeReport] generates findings.
type analyzeOptions struct {
	// baseline is a previous report for comparison. Nil means no baseline.
	baseline *report
	// dexReaders holds all named archive readers containing DEX files.
	// Empty means DEX scanning is skipped (e.g. baseline-only comparison).
	dexReaders []namedReader
	// maxEntryBytes is the size limit for individual ZIP entries.
	maxEntryBytes int64
}

// SigningInfo holds code signing and certificate information extracted
// from a mobile application package.
type SigningInfo struct {
	// Scheme describes the signing schemes detected.
	// Android examples: "v1", "v2", "v3", "v1+v2", "v1+v3".
	// iOS: "apple".
	Scheme string `json:"scheme"`
	// Certificates lists the signing certificates found.
	Certificates []CertSummary `json:"certificates,omitempty"`
}

// CertSummary holds a summary of an X.509 certificate used for code signing.
type CertSummary struct {
	// Subject is the certificate subject (typically CN or O).
	Subject string `json:"subject"`
	// Issuer is the certificate issuer.
	Issuer string `json:"issuer"`
	// NotBefore is the certificate validity start in RFC 3339 format.
	NotBefore string `json:"not_before"`
	// NotAfter is the certificate validity end in RFC 3339 format.
	NotAfter string `json:"not_after"`
	// SHA256Fingerprint is the hex-encoded SHA-256 fingerprint of the DER certificate.
	SHA256Fingerprint string `json:"sha256_fingerprint"`
	// SerialNumber is the certificate serial number in decimal.
	SerialNumber string `json:"serial_number"`
}

// SDKConstraints holds the SDK and OS version requirements extracted
// from the application manifest.
type SDKConstraints struct {
	// MinSDK is the minimum SDK/OS version required.
	// Android: minSdkVersion (e.g. "21"). iOS: MinimumOSVersion (e.g. "15.0").
	MinSDK string `json:"min_sdk,omitempty"`
	// TargetSDK is the target SDK version (Android only).
	// Empty for iOS packages.
	TargetSDK string `json:"target_sdk,omitempty"`
}

// Identity holds the package identifier and display name.
type Identity struct {
	// Identifier is the package name (Android) or bundle ID (iOS).
	Identifier string `json:"identifier"`
	// DisplayName is the user-visible application name.
	DisplayName string `json:"display_name"`
}

// Version holds marketing and build version strings.
type Version struct {
	// Marketing is the user-facing version string
	// (Android versionName / iOS CFBundleShortVersionString).
	Marketing string `json:"marketing"`
	// Build is the internal build identifier
	// (Android versionCode / iOS CFBundleVersion).
	Build string `json:"build"`
}

// EntryPoint describes the main entry point of the application.
type EntryPoint struct {
	// Kind classifies the entry point ("activity", "executable", or "unknown").
	Kind string `json:"kind"`
	// Name is the fully qualified name of the entry point.
	Name string `json:"name"`
}

// Permission represents a declared permission in a mobile application package.
type Permission struct {
	// Canonical is a cross-platform classification (e.g. "camera", "location").
	// Empty if no mapping is available.
	Canonical string `json:"canonical,omitempty"`
	// RawName is the platform-specific permission identifier
	// (e.g. "android.permission.CAMERA", "NSCameraUsageDescription").
	RawName string `json:"raw_name"`
	// Source indicates where the permission was declared
	// ("manifest", "info_plist", or "entitlement").
	Source string `json:"source"`
}

// IconAsset holds the extracted icon data.
type IconAsset struct {
	// Path is the archive-internal path of the icon file.
	Path string `json:"path"`
	// Bytes contains the raw icon data.
	// Excluded from JSON serialization to avoid bloating output.
	Bytes []byte `json:"-"`
	// Format describes the image format (e.g. "png", "jpeg").
	Format string `json:"format"`
	// Width is the icon width in pixels (0 if unknown).
	Width int `json:"width"`
	// Height is the icon height in pixels (0 if unknown).
	Height int `json:"height"`
}

// androidReport carries Android-specific data from an APK inspection.
type androidReport struct {
	// RawManifest holds the parsed AndroidManifest fields.
	RawManifest map[string]any `json:"raw_manifest,omitempty"`
}

// iosReport carries iOS-specific data from an IPA inspection.
type iosReport struct {
	// InfoPlist holds the parsed Info.plist dictionary.
	InfoPlist map[string]any `json:"info_plist,omitempty"`
	// Entitlements holds the parsed entitlements dictionary.
	Entitlements map[string]any `json:"entitlements,omitempty"`
}

// asAndroid extracts the [androidReport] from a [report].
// It returns nil and false if the report is not for Android.
func asAndroid(r report) (*androidReport, bool) {
	ar, ok := r.PlatformData.(*androidReport)
	return ar, ok
}

// asIOS extracts the [iosReport] from a [report].
// It returns nil and false if the report is not for iOS.
func asIOS(r report) (*iosReport, bool) {
	ir, ok := r.PlatformData.(*iosReport)
	return ir, ok
}

// InspectResult is the single output of an inspection performed by
// [InspectFile] or [Inspect]. It combines package metadata, security-relevant
// facts, analysis findings, and diagnostics into one flat structure.
//
// This is the primary result type for the mobilepkg API. It contains
// everything needed for CI quality gates, security review, and release
// comparison in a single value.
type InspectResult struct {
	// Platform is the detected platform (android or ios).
	Platform Platform `json:"platform"`
	// Format identifies the specific packaging format (e.g. "apk", "ipa").
	Format Format `json:"format"`
	// Identity holds the package identifier and display name.
	Identity Identity `json:"identity"`
	// Version holds the marketing and build version strings.
	Version Version `json:"version"`
	// Entry holds the main entry point of the application.
	Entry EntryPoint `json:"entry"`
	// SDK holds the SDK and OS version constraints.
	SDK SDKConstraints `json:"sdk"`
	// Signing holds code signing and certificate information.
	// Nil when signing information is not available.
	Signing *SigningInfo `json:"signing,omitempty"`
	// Icon holds the extracted icon asset, if available.
	// Nil when no icon was found in the package.
	Icon *IconAsset `json:"icon,omitempty"`

	// Debuggable indicates whether the application is marked as debuggable.
	Debuggable bool `json:"debuggable"`
	// AllowBackup indicates whether the application allows data backup.
	AllowBackup bool `json:"allow_backup"`
	// UsesCleartextTraffic indicates whether the application allows
	// cleartext (unencrypted HTTP) network traffic.
	UsesCleartextTraffic bool `json:"uses_cleartext_traffic"`
	// NetworkSecurityConfig is the resource reference to the network
	// security configuration (Android only, e.g. "@xml/network_security_config").
	// Empty when not declared or for iOS packages.
	NetworkSecurityConfig string `json:"network_security_config,omitempty"`
	// NSCPolicy holds the parsed network security configuration.
	// Nil when no network_security_config.xml is found or for iOS packages.
	NSCPolicy *NetworkSecurityPolicy `json:"nsc_policy,omitempty"`
	// Permissions lists the declared permissions.
	Permissions []Permission `json:"permissions"`
	// ExportedComponents lists components that are exported and accessible
	// to other applications.
	ExportedComponents []ExportedComponent `json:"exported_components"`
	// NetworkEndpoints lists network endpoints found in the package metadata.
	NetworkEndpoints []NetworkEndpoint `json:"network_endpoints"`

	// Findings holds security-relevant observations from analysis.
	Findings []Finding `json:"findings"`
	// SecretCandidates lists potential secrets, tokens, or credentials.
	SecretCandidates []SecretCandidate `json:"secret_candidates"`

	// Diff holds the comparison against a baseline, if provided.
	Diff *Diff `json:"diff,omitempty"`

	// Diagnostics collects non-fatal issues encountered during inspection
	// and analysis.
	Diagnostics []Diagnostic `json:"diagnostics"`
}

// ExportedComponent represents an application component that is accessible
// to other applications on the device. On Android this includes activities,
// services, broadcast receivers, and content providers that are explicitly
// or implicitly exported.
type ExportedComponent struct {
	// Kind is the component type: "activity", "service", "receiver", or "provider".
	Kind string `json:"kind"`
	// Name is the fully qualified component name.
	Name string `json:"name"`
	// Exported indicates whether the component is exported.
	Exported bool `json:"exported"`
	// Permission is the permission required to access this component, if any.
	Permission string `json:"permission,omitempty"`
	// Authorities holds the content provider authorities (provider only).
	Authorities string `json:"authorities,omitempty"`
	// IntentFilters holds parsed intent-filter data for the component.
	IntentFilters []IntentFilter `json:"intent_filters,omitempty"`
}

// IntentFilter holds parsed intent-filter data from an Android manifest.
// Each filter declares what intents the component can respond to.
type IntentFilter struct {
	// Actions lists the intent actions (e.g. "android.intent.action.VIEW").
	Actions []string `json:"actions,omitempty"`
	// Categories lists the intent categories (e.g. "android.intent.category.DEFAULT").
	Categories []string `json:"categories,omitempty"`
	// Data lists the data specifications (scheme, host, path) for the filter.
	Data []DataSpec `json:"data,omitempty"`
}

// DataSpec holds scheme/host/path from an Android intent-filter <data> element.
type DataSpec struct {
	// Scheme is the URI scheme (e.g. "https", "myapp").
	Scheme string `json:"scheme,omitempty"`
	// Host is the hostname or authority.
	Host string `json:"host,omitempty"`
	// Path is the URI path.
	Path string `json:"path,omitempty"`
}

// NetworkSecurityPolicy holds a partial summary of an Android
// network_security_config.xml file. It captures the base-config
// cleartext policy, top-level domain-configs (domains + cleartext +
// pin-set presence), and base-config trust-anchor sources.
//
// Limitations: nested domain-configs, per-domain trust-anchors,
// and debug-overrides are not parsed. This provides a useful
// triage signal but is not a full representation of the config.
type NetworkSecurityPolicy struct {
	// CleartextPermitted indicates whether the base config allows
	// cleartext (HTTP) traffic.
	CleartextPermitted bool `json:"cleartext_permitted"`
	// DomainConfigs lists per-domain security configurations.
	DomainConfigs []DomainConfig `json:"domain_configs,omitempty"`
	// TrustAnchors lists the trust anchor sources (e.g. "system", "user",
	// or a raw certificate reference).
	TrustAnchors []string `json:"trust_anchors,omitempty"`
	// HasPinSet is true if any domain config includes certificate pinning.
	HasPinSet bool `json:"has_pin_set"`
}

// DomainConfig represents a <domain-config> entry in
// network_security_config.xml.
type DomainConfig struct {
	// Domains lists the domains this config applies to.
	Domains []string `json:"domains"`
	// CleartextPermitted indicates whether cleartext traffic is allowed
	// for these domains.
	CleartextPermitted bool `json:"cleartext_permitted"`
	// HasPinSet is true if this domain config includes certificate pinning.
	HasPinSet bool `json:"has_pin_set"`
}

// NetworkEndpoint represents a network endpoint found in the package metadata.
type NetworkEndpoint struct {
	// Scheme is the URL scheme (e.g. "https", "http", "wss").
	Scheme string `json:"scheme,omitempty"`
	// Host is the hostname or IP address.
	Host string `json:"host"`
	// Port is the port number, if specified.
	Port string `json:"port,omitempty"`
	// Path is the URL path, if available.
	Path string `json:"path,omitempty"`
	// Source describes where this endpoint was found
	// (e.g. "manifest", "info_plist", "entitlement").
	Source string `json:"source"`
	// Confidence indicates how certain the detection is.
	Confidence Confidence `json:"confidence"`
}

// SecretCandidate represents a potential secret, token, or credential
// found in the package. Raw values are never exposed; only a short
// masked prefix is provided for human identification.
type SecretCandidate struct {
	// Kind classifies the secret type (e.g. "api_key", "token", "aws_key").
	Kind string `json:"kind"`
	// MaskedValue shows a short prefix of the secret with the rest redacted.
	MaskedValue string `json:"masked_value"`
	// Source describes where this candidate was found.
	Source string `json:"source"`
	// Confidence indicates how certain the detection is.
	Confidence Confidence `json:"confidence"`
}

// Diff represents the structured differences between two report values.
type Diff struct {
	// OldPlatform is the platform of the old report.
	OldPlatform Platform `json:"old_platform"`
	// NewPlatform is the platform of the new report.
	NewPlatform Platform `json:"new_platform"`
	// IdentityChanged is true when the identity fields differ.
	IdentityChanged bool `json:"identity_changed"`
	// VersionChanged is true when the version fields differ.
	VersionChanged bool `json:"version_changed"`
	// EntryChanged is true when the entry point fields differ.
	EntryChanged bool `json:"entry_changed"`
	// AddedPermissions lists permissions present in the new report but not the old.
	AddedPermissions []Permission `json:"added_permissions,omitempty"`
	// RemovedPermissions lists permissions present in the old report but not the new.
	RemovedPermissions []Permission `json:"removed_permissions,omitempty"`
	// AddedComponents lists exported components present in the new report but not the old.
	AddedComponents []ExportedComponent `json:"added_components,omitempty"`
	// RemovedComponents lists exported components present in the old report but not the new.
	RemovedComponents []ExportedComponent `json:"removed_components,omitempty"`
	// AddedEndpoints lists network endpoints present in the new report but not the old.
	AddedEndpoints []NetworkEndpoint `json:"added_endpoints,omitempty"`
	// RemovedEndpoints lists network endpoints present in the old report but not the new.
	RemovedEndpoints []NetworkEndpoint `json:"removed_endpoints,omitempty"`
}
