package android

import (
	"archive/zip"
	"bytes"
	"fmt"
	"image/png"
	"io"
	"os"
	"sync"

	aab "github.com/izinga/aab-parser"
	"github.com/izinga/aab-parser/pb"
	"google.golang.org/protobuf/proto"
)

// InspectAAB extracts information from an Android App Bundle (AAB).
// The AAB manifest is encoded in protobuf format. Identity, version,
// entry point, permissions, SDK constraints, and platform raw data are
// extracted directly from the protobuf manifest without the aab-parser
// library. The library is only initialised when Icon or Label resource
// resolution is required, because its parseManifest method contains a
// debug fmt.Println that pollutes stdout.
//
// iconSizePx selects the icon density closest to the given pixel size;
// zero means the best available candidate.
func InspectAAB(r io.ReaderAt, size int64, sections uint64, iconSizePx int, maxEntryBytes int64) (*Result, []Diagnostic, error) {
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
	)

	// Parse protobuf manifest — used by all sections.
	xmlNode, walkErr := parseAABManifestXML(r, size, maxEntryBytes)
	if walkErr != nil {
		return nil, nil, fmt.Errorf("android/aab: failed to parse manifest: %w", walkErr)
	}

	rootElem := xmlNode.GetElement()

	// Identity (package from protobuf, label best-effort from protobuf)
	if sections&(1<<bitIdentity) != 0 && rootElem != nil {
		result.PackageName = xmlAttrValue(rootElem, attrPackage)
		result.Label = findAABApplicationLabel(xmlNode)
	}

	// Version
	if sections&(1<<bitVersion) != 0 && rootElem != nil {
		result.VersionName = xmlAttrValue(rootElem, attrVersionName)
		result.VersionCode = xmlAttrValue(rootElem, attrVersionCode)
	}

	// EntryPoint
	if sections&(1<<bitEntryPoint) != 0 {
		result.MainActivity = findAABMainActivity(xmlNode)
	}

	// Permissions
	if sections&(1<<bitPermissions) != 0 {
		result.Permissions = findAABPermissions(xmlNode)
	}

	// SDK constraints
	if sections&(1<<bitSDK) != 0 {
		result.MinSDK, result.TargetSDK = findAABUsesSdk(xmlNode)
	}

	// PlatformRaw
	if sections&(1<<bitPlatformRaw) != 0 && rootElem != nil {
		result.RawManifest = map[string]any{
			attrPackage:     xmlAttrValue(rootElem, attrPackage),
			attrVersionCode: xmlAttrValue(rootElem, attrVersionCode),
			attrVersionName: xmlAttrValue(rootElem, attrVersionName),
		}
	}

	// Icon and Label resource resolution need the aab-parser library.
	// Only initialise the library when one of these is actually needed.
	needLabel := sections&(1<<bitIdentity) != 0 && result.Label == ""
	needIcon := sections&(1<<bitIcon) != 0

	if needLabel || needIcon {
		a, libErr := openAABQuiet(r, size)
		if libErr != nil {
			if needIcon {
				diags = append(diags, Diagnostic{
					Code:     "icon.not_found",
					Severity: sevWarn,
					Message:  fmt.Sprintf("failed to initialise AAB parser for icon: %v", libErr),
				})
			}
		} else {
			if needLabel {
				result.Label = a.Label(nil)
			}
			if needIcon {
				var iconConfig *pb.Configuration
				if iconSizePx > 0 {
					iconConfig = &pb.Configuration{Density: uint32(iconSizePx * 160 / 48)}
				}
				img, iconErr := a.Icon(iconConfig)
				if iconErr == nil && img != nil {
					var iconBuf bytes.Buffer
					if encErr := png.Encode(&iconBuf, img); encErr == nil {
						result.IconBytes = iconBuf.Bytes()
						result.IconFormat = "png"
						bounds := img.Bounds()
						result.IconWidth = bounds.Dx()
						result.IconHeight = bounds.Dy()
					} else {
						diags = append(diags, Diagnostic{
							Code:     "icon.encode_failed",
							Severity: sevWarn,
							Message:  fmt.Sprintf("failed to encode icon as PNG: %v", encErr),
						})
					}
				} else {
					diags = append(diags, Diagnostic{
						Code:     "icon.not_found",
						Severity: sevWarn,
						Message:  fmt.Sprintf("failed to extract icon: %v", iconErr),
					})
				}
			}
		}
	}

	return result, diags, nil
}

// parseAABManifestXML reads and parses the protobuf-encoded
// AndroidManifest.xml from an AAB archive.
func parseAABManifestXML(r io.ReaderAt, size int64, maxEntryBytes int64) (*pb.XmlNode, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, err
	}

	data, err := readZipFile(zr, "base/manifest/AndroidManifest.xml", maxEntryBytes)
	if err != nil {
		return nil, err
	}

	var node pb.XmlNode
	if err := proto.Unmarshal(data, &node); err != nil {
		return nil, fmt.Errorf("failed to unmarshal AAB manifest proto: %w", err)
	}
	return &node, nil
}

// findAABApplicationLabel attempts to extract the application label from
// the protobuf manifest. It checks the <application> element's "label"
// attribute value. Returns "" if the label is a resource reference that
// requires library-level resolution.
func findAABApplicationLabel(root *pb.XmlNode) string {
	elem := root.GetElement()
	if elem == nil {
		return ""
	}
	for _, child := range elem.Child {
		ce := child.GetElement()
		if ce == nil || ce.Name != "application" {
			continue
		}
		// Try the string value of the label attribute.
		for _, attr := range ce.Attribute {
			if attr.Name == "label" {
				if attr.Value != "" {
					return attr.Value
				}
				// Check compiled_item for an inline string.
				if item := attr.CompiledItem; item != nil {
					if str := item.GetStr(); str != nil {
						return str.GetValue()
					}
				}
				return ""
			}
		}
	}
	return ""
}

// findAABMainActivity walks the XmlNode tree to find the MAIN/LAUNCHER
// activity name.
func findAABMainActivity(root *pb.XmlNode) string {
	elem := root.GetElement()
	if elem == nil {
		return ""
	}

	for _, child := range elem.Child {
		ce := child.GetElement()
		if ce == nil || ce.Name != "application" {
			continue
		}

		for _, actChild := range ce.Child {
			ae := actChild.GetElement()
			if ae == nil || ae.Name != "activity" {
				continue
			}

			actName := xmlAttrValue(ae, "name")

			for _, ifChild := range ae.Child {
				ife := ifChild.GetElement()
				if ife == nil || ife.Name != "intent-filter" {
					continue
				}
				if isMainLauncherFilter(ife) {
					return actName
				}
			}
		}
	}
	return ""
}

// isMainLauncherFilter checks if an intent-filter element contains
// both android.intent.action.MAIN and android.intent.category.LAUNCHER.
func isMainLauncherFilter(elem *pb.XmlElement) bool {
	hasMain := false
	hasLauncher := false

	for _, child := range elem.Child {
		ce := child.GetElement()
		if ce == nil {
			continue
		}
		name := xmlAttrValue(ce, "name")
		switch ce.Name {
		case "action":
			if name == "android.intent.action.MAIN" {
				hasMain = true
			}
		case "category":
			if name == "android.intent.category.LAUNCHER" {
				hasLauncher = true
			}
		}
	}

	return hasMain && hasLauncher
}

// findAABPermissions walks the XmlNode tree to extract uses-permission names.
func findAABPermissions(root *pb.XmlNode) []string {
	elem := root.GetElement()
	if elem == nil {
		return nil
	}

	var perms []string
	for _, child := range elem.Child {
		ce := child.GetElement()
		if ce == nil || ce.Name != "uses-permission" {
			continue
		}
		name := xmlAttrValue(ce, "name")
		if name != "" {
			perms = append(perms, name)
		}
	}
	return perms
}

// findAABUsesSdk walks the XmlNode tree to find <uses-sdk> and extract
// minSdkVersion and targetSdkVersion attributes.
func findAABUsesSdk(root *pb.XmlNode) (minSDK, targetSDK string) {
	elem := root.GetElement()
	if elem == nil {
		return "", ""
	}

	for _, child := range elem.Child {
		ce := child.GetElement()
		if ce == nil || ce.Name != "uses-sdk" {
			continue
		}
		return xmlAttrValue(ce, "minSdkVersion"), xmlAttrValue(ce, "targetSdkVersion")
	}
	return "", ""
}

// xmlAttrValue returns the value of an attribute by name from an XmlElement.
func xmlAttrValue(elem *pb.XmlElement, name string) string {
	for _, attr := range elem.Attribute {
		if attr.Name == name {
			return attr.Value
		}
	}
	return ""
}

// aabStdoutMu serialises os.Stdout swaps across concurrent openAABQuiet calls.
var aabStdoutMu sync.Mutex

// openAABQuiet calls aab.OpenZipReader while suppressing its debug
// fmt.Println output. It redirects os.Stdout to the write end of an
// os.Pipe (so concurrent writes do not get EBADF) and uses defer to
// guarantee restoration even if the library panics.
func openAABQuiet(r io.ReaderAt, size int64) (*aab.Aab, error) {
	pr, pw, err := os.Pipe()
	if err != nil {
		// Pipe creation failed; fall through without suppression.
		return aab.OpenZipReader(r, size)
	}

	// Drain the pipe in background so writes never block.
	go func() {
		buf := make([]byte, 512)
		for {
			if _, rerr := pr.Read(buf); rerr != nil {
				break
			}
		}
		_ = pr.Close()
	}()

	aabStdoutMu.Lock()
	defer aabStdoutMu.Unlock()

	orig := os.Stdout
	os.Stdout = pw
	defer func() {
		os.Stdout = orig
		_ = pw.Close()
	}()

	return aab.OpenZipReader(r, size)
}
