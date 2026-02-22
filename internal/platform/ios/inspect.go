package ios

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"image"
	"io"
	"path"
	"strings"

	// Register image decoders for icon extraction.
	_ "image/jpeg"
	_ "image/png"

	"howett.net/plist"
)

// Sentinel errors for iOS inspection failures.
var (
	// ErrInfoPlistNotFound indicates that Info.plist is missing from the IPA.
	ErrInfoPlistNotFound = errors.New("ios: Info.plist not found in IPA archive")
	// ErrInfoPlistParseFailed indicates that Info.plist could not be parsed.
	ErrInfoPlistParseFailed = errors.New("ios: failed to parse Info.plist")
)

// Result holds the extracted data from an iOS IPA.
type Result struct {
	BundleID         string
	DisplayName      string
	ShortVersion     string
	BundleVersion    string
	Executable       string
	MinimumOSVersion string
	Signing          *ProvisionInfo
	Permissions      []PermissionEntry
	IconPath         string
	IconBytes        []byte
	IconWidth        int
	IconHeight       int
	IconFormat       string
	InfoPlist        map[string]any
	Entitlements     map[string]any
}

// PermissionEntry represents a single iOS permission or entitlement.
type PermissionEntry struct {
	RawName string
	Source  string // "info_plist" or "entitlement"
}

// Diagnostic is a non-fatal issue found during iOS inspection.
type Diagnostic struct {
	Code     string
	Severity string
	Message  string
}

// Inspect extracts information from an IPA ZIP archive.
// The sections parameter is a bitmask controlling which data to extract.
// Bit positions match the mobilepkg.Section constants:
//
//	bit 0: Identity, bit 1: Version, bit 2: EntryPoint,
//	bit 3: Permissions, bit 4: Icon, bit 5: PlatformRaw
func Inspect(zr *zip.Reader, sections uint64) (*Result, []Diagnostic, error) {
	appDir, infoPlistPath, err := findInfoPlist(zr)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInfoPlistNotFound, err)
	}

	plistData, err := readZipFile(zr, infoPlistPath)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInfoPlistNotFound, err)
	}

	var info map[string]any
	if _, err := plist.Unmarshal(plistData, &info); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInfoPlistParseFailed, err)
	}

	result := &Result{}
	var diags []Diagnostic

	const (
		bitIdentity    = 0
		bitVersion     = 1
		bitEntryPoint  = 2
		bitPermissions = 3
		bitIcon        = 4
		bitPlatformRaw = 5
		bitSDK         = 6
		bitSigning     = 7
	)

	// Identity
	if sections&(1<<bitIdentity) != 0 {
		result.BundleID = stringFromPlist(info, "CFBundleIdentifier")
		result.DisplayName = stringFromPlist(info, "CFBundleDisplayName")
		if result.DisplayName == "" {
			result.DisplayName = stringFromPlist(info, "CFBundleName")
		}
	}

	// Version
	if sections&(1<<bitVersion) != 0 {
		result.ShortVersion = stringFromPlist(info, "CFBundleShortVersionString")
		result.BundleVersion = stringFromPlist(info, "CFBundleVersion")
	}

	// EntryPoint
	if sections&(1<<bitEntryPoint) != 0 {
		result.Executable = stringFromPlist(info, "CFBundleExecutable")
	}

	// Entitlements — needed by both Permissions and PlatformRaw.
	if sections&((1<<bitPermissions)|(1<<bitPlatformRaw)) != 0 {
		entData, entErr := readZipFile(zr, appDir+"embedded.mobileprovision")
		if entErr == nil {
			result.Entitlements = parseEntitlements(entData)
		}
	}

	// Permissions
	if sections&(1<<bitPermissions) != 0 {
		result.Permissions = extractPermissions(info)

		for k := range result.Entitlements {
			result.Permissions = append(result.Permissions, PermissionEntry{
				RawName: k,
				Source:  "entitlement",
			})
		}
	}

	// Icon
	if sections&(1<<bitIcon) != 0 {
		iconPath, iconData, iconErr := extractIcon(zr, info, appDir)
		if iconErr != nil {
			diags = append(diags, Diagnostic{
				Code:     "icon.not_found",
				Severity: "warn",
				Message:  fmt.Sprintf("failed to extract icon: %v", iconErr),
			})
		} else {
			result.IconPath = iconPath
			result.IconBytes = iconData
			result.IconFormat = detectImageFormat(iconPath)
			img, _, decErr := image.Decode(bytes.NewReader(iconData))
			if decErr == nil {
				bounds := img.Bounds()
				result.IconWidth = bounds.Dx()
				result.IconHeight = bounds.Dy()
			} else {
				diags = append(diags, Diagnostic{
					Code:     "icon.decode_failed",
					Severity: "info",
					Message:  fmt.Sprintf("icon found but could not decode image: %v", decErr),
				})
			}
		}
	}

	// PlatformRaw
	if sections&(1<<bitPlatformRaw) != 0 {
		result.InfoPlist = info
	}

	// SDK constraints
	if sections&(1<<bitSDK) != 0 {
		result.MinimumOSVersion = stringFromPlist(info, "MinimumOSVersion")
	}

	// Signing
	if sections&(1<<bitSigning) != 0 {
		provData, provErr := readZipFile(zr, appDir+"embedded.mobileprovision")
		if provErr == nil {
			provInfo, parseErr := ExtractProvisioningInfo(provData)
			if parseErr != nil {
				diags = append(diags, Diagnostic{
					Code:     "signing.parse_failed",
					Severity: "warn",
					Message:  fmt.Sprintf("failed to parse provisioning profile: %v", parseErr),
				})
			} else {
				result.Signing = provInfo
			}
		}
	}

	return result, diags, nil
}

func findInfoPlist(zr *zip.Reader) (appDir, plistPath string, err error) {
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "Payload/") && strings.HasSuffix(f.Name, ".app/Info.plist") {
			parts := strings.SplitN(f.Name, "/", 3)
			if len(parts) >= 2 {
				appDir = parts[0] + "/" + parts[1] + "/"
			}
			return appDir, f.Name, nil
		}
	}
	return "", "", fmt.Errorf("info.plist not found in IPA archive")
}

func readZipFile(zr *zip.Reader, name string) ([]byte, error) {
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer func() { _ = rc.Close() }()
		return io.ReadAll(rc)
	}
	return nil, fmt.Errorf("file %q not found in archive", name)
}

func stringFromPlist(info map[string]any, key string) string {
	v, ok := info[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Sprintf("%v", v)
	}
	return s
}

// extractPermissions finds NS*UsageDescription keys in Info.plist.
func extractPermissions(info map[string]any) []PermissionEntry {
	var perms []PermissionEntry
	for k := range info {
		if strings.HasPrefix(k, "NS") && strings.HasSuffix(k, "UsageDescription") {
			perms = append(perms, PermissionEntry{
				RawName: k,
				Source:  "info_plist",
			})
		}
	}
	return perms
}

// parseEntitlements attempts to extract the entitlements dictionary from
// the embedded.mobileprovision file. The file is a CMS (PKCS#7) signed
// plist. We do a best-effort extraction by looking for the plist XML
// inside the binary data.
func parseEntitlements(data []byte) map[string]any {
	// Look for plist XML embedded within the CMS blob.
	start := bytes.Index(data, []byte("<?xml"))
	if start < 0 {
		return nil
	}
	end := bytes.Index(data[start:], []byte("</plist>"))
	if end < 0 {
		return nil
	}
	end += start + len("</plist>")

	var provision map[string]any
	if _, err := plist.Unmarshal(data[start:end], &provision); err != nil {
		return nil
	}

	ent, ok := provision["Entitlements"]
	if !ok {
		return nil
	}
	entMap, ok := ent.(map[string]any)
	if !ok {
		return nil
	}
	return entMap
}

// extractIcon finds the best icon file in the IPA.
func extractIcon(zr *zip.Reader, info map[string]any, appDir string) (string, []byte, error) {
	// Try CFBundleIcons -> CFBundlePrimaryIcon -> CFBundleIconFiles
	iconNames := findIconNames(info)

	// Try each icon candidate
	for _, name := range iconNames {
		// The icon name may or may not have an extension; try both.
		candidates := []string{name, name + ".png", name + "@2x.png", name + "@3x.png"}
		for _, c := range candidates {
			p := appDir + c
			data, err := readZipFile(zr, p)
			if err == nil {
				return p, data, nil
			}
		}
	}

	// Fallback: scan for any PNG file that looks like an icon.
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, appDir) && strings.Contains(f.Name, "Icon") &&
			strings.HasSuffix(strings.ToLower(f.Name), ".png") {
			data, err := readZipFile(zr, f.Name)
			if err == nil {
				return f.Name, data, nil
			}
		}
	}

	return "", nil, fmt.Errorf("no icon found")
}

func findIconNames(info map[string]any) []string {
	var names []string

	// CFBundleIcons path
	if icons, ok := info["CFBundleIcons"].(map[string]any); ok {
		if primary, ok := icons["CFBundlePrimaryIcon"].(map[string]any); ok {
			if files, ok := primary["CFBundleIconFiles"].([]any); ok {
				for _, f := range files {
					if s, ok := f.(string); ok {
						names = append(names, s)
					}
				}
			}
		}
	}

	// CFBundleIconFiles (older format)
	if files, ok := info["CFBundleIconFiles"].([]any); ok {
		for _, f := range files {
			if s, ok := f.(string); ok {
				names = append(names, s)
			}
		}
	}

	// CFBundleIconFile (single icon)
	if f, ok := info["CFBundleIconFile"].(string); ok && f != "" {
		names = append(names, f)
	}

	return names
}

func detectImageFormat(p string) string {
	ext := strings.ToLower(path.Ext(p))
	switch ext {
	case ".png":
		return "png"
	case ".jpg", ".jpeg":
		return "jpeg"
	default:
		return ""
	}
}
