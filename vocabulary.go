package mobilepkg

// The finding vocabulary and the archive members the analysis cites. These
// strings are part of the JSON contract -- a consumer filters on Category and
// keys off Evidence.ArchivePath -- so they are named once here rather than
// repeated at each site, where a typo would change the published output without
// failing the build.
const (
	// Finding categories.
	categoryManifest    = "manifest"
	categoryEntitlement = "entitlement"
	categoryCleartext   = "cleartext"

	// Archive members cited as evidence.
	pathAndroidManifest       = "AndroidManifest.xml"
	pathNetworkSecurityConfig = "network_security_config.xml"
	pathInfoPlist             = "Info.plist"

	// entitlementGetTaskAllow is the iOS entitlement that marks a debuggable build.
	entitlementGetTaskAllow = "get-task-allow"

	// codeUnsupportedFormat is the diagnostic code for an input mobilepkg cannot identify.
	codeUnsupportedFormat = "format.unsupported"
)
