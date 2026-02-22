package ios

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math/big"
	"testing"
	"time"

	"howett.net/plist"
)

func TestInspect_AllSections(t *testing.T) {
	certDER := createCertificateDER(t)
	infoPlist := mustMarshalPlist(t, map[string]any{
		"CFBundleIdentifier":         "com.example.testapp",
		"CFBundleName":               "Test App",
		"CFBundleShortVersionString": "2.0.1",
		"CFBundleVersion":            "100",
		"CFBundleExecutable":         "TestApp",
		"MinimumOSVersion":           "15.0",
		"NSCameraUsageDescription":   "camera",
		"CFBundleIcons": map[string]any{
			"CFBundlePrimaryIcon": map[string]any{
				"CFBundleIconFiles": []any{"AppIcon60x60"},
			},
		},
	})
	profile := createProvisioningProfile(t, certDER, map[string]any{
		"aps-environment": "development",
	})

	zr := newZipReaderForTest(t, map[string][]byte{
		"Payload/TestApp.app/Info.plist":               infoPlist,
		"Payload/TestApp.app/AppIcon60x60@2x.png":      createPNGIcon(t),
		"Payload/TestApp.app/embedded.mobileprovision": profile,
	})

	result, diags, err := Inspect(zr, 0xFF, 1<<20)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(diags) != 0 {
		t.Fatalf("diags = %#v, want none", diags)
	}

	if result.BundleID != "com.example.testapp" {
		t.Fatalf("BundleID = %q, want %q", result.BundleID, "com.example.testapp")
	}
	if result.DisplayName != "Test App" {
		t.Fatalf("DisplayName = %q, want %q", result.DisplayName, "Test App")
	}
	if result.ShortVersion != "2.0.1" || result.BundleVersion != "100" {
		t.Fatalf("version = %q/%q, want %q/%q", result.ShortVersion, result.BundleVersion, "2.0.1", "100")
	}
	if result.Executable != "TestApp" {
		t.Fatalf("Executable = %q, want %q", result.Executable, "TestApp")
	}
	if result.MinimumOSVersion != "15.0" {
		t.Fatalf("MinimumOSVersion = %q, want %q", result.MinimumOSVersion, "15.0")
	}
	if result.IconPath != "Payload/TestApp.app/AppIcon60x60@2x.png" {
		t.Fatalf("IconPath = %q", result.IconPath)
	}
	if result.IconFormat != "png" || result.IconWidth != 2 || result.IconHeight != 3 {
		t.Fatalf("icon = %q %dx%d", result.IconFormat, result.IconWidth, result.IconHeight)
	}
	if result.InfoPlist == nil || result.Entitlements == nil {
		t.Fatalf("InfoPlist/Entitlements should be populated: %#v %#v", result.InfoPlist, result.Entitlements)
	}
	if result.Signing == nil {
		t.Fatal("Signing = nil, want parsed provisioning info")
	}
	if result.Signing.TeamID != "TEAM123456" || result.Signing.ProfileName != "Test Profile" {
		t.Fatalf("Signing = %#v", result.Signing)
	}

	seenPermissions := map[string]bool{}
	for _, p := range result.Permissions {
		seenPermissions[p.RawName] = true
	}
	if !seenPermissions["NSCameraUsageDescription"] || !seenPermissions["aps-environment"] {
		t.Fatalf("permissions = %#v", result.Permissions)
	}
}

func TestInspect_ErrorsAndDiagnostics(t *testing.T) {
	t.Run("missing info plist", func(t *testing.T) {
		zr := newZipReaderForTest(t, map[string][]byte{
			"Payload/TestApp.app/readme.txt": []byte("hello"),
		})

		if _, _, err := Inspect(zr, 0xFF, 1<<20); !errors.Is(err, ErrInfoPlistNotFound) {
			t.Fatalf("err = %v, want ErrInfoPlistNotFound", err)
		}
	})

	t.Run("invalid info plist", func(t *testing.T) {
		zr := newZipReaderForTest(t, map[string][]byte{
			"Payload/TestApp.app/Info.plist": []byte("not a plist"),
		})

		if _, _, err := Inspect(zr, 0xFF, 1<<20); !errors.Is(err, ErrInfoPlistParseFailed) {
			t.Fatalf("err = %v, want ErrInfoPlistParseFailed", err)
		}
	})

	t.Run("invalid icon emits diagnostic", func(t *testing.T) {
		infoPlist := mustMarshalPlist(t, map[string]any{
			"CFBundleIdentifier": "com.example.testapp",
			"CFBundleIcons": map[string]any{
				"CFBundlePrimaryIcon": map[string]any{
					"CFBundleIconFiles": []any{"AppIcon"},
				},
			},
		})

		zr := newZipReaderForTest(t, map[string][]byte{
			"Payload/TestApp.app/Info.plist":               infoPlist,
			"Payload/TestApp.app/AppIcon.png":              []byte("not an image"),
			"Payload/TestApp.app/embedded.mobileprovision": []byte("missing plist"),
		})

		result, diags, err := Inspect(zr, (1<<0)|(1<<4), 1<<20)
		if err != nil {
			t.Fatalf("Inspect: %v", err)
		}
		if result.IconPath != "Payload/TestApp.app/AppIcon.png" {
			t.Fatalf("IconPath = %q, want AppIcon.png path", result.IconPath)
		}

		found := false
		for _, d := range diags {
			if d.Code == "icon.decode_failed" {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected icon.decode_failed diagnostic, got %#v", diags)
		}
	})
}

func TestIOSHelpers(t *testing.T) {
	infoPlist := mustMarshalPlist(t, map[string]any{"CFBundleIdentifier": "com.example.testapp"})
	zr := newZipReaderForTest(t, map[string][]byte{
		"Payload/TestApp.app/Info.plist": infoPlist,
		"data.txt":                       []byte("abcd"),
	})

	appDir, plistPath, err := findInfoPlist(zr)
	if err != nil {
		t.Fatalf("findInfoPlist: %v", err)
	}
	if appDir != "Payload/TestApp.app/" || plistPath != "Payload/TestApp.app/Info.plist" {
		t.Fatalf("findInfoPlist = %q %q", appDir, plistPath)
	}

	if _, err := readZipFile(zr, "data.txt", 3); err == nil {
		t.Fatal("readZipFile error = nil, want size limit error")
	}
	if _, err := readZipFile(zr, "missing.txt", 0); err == nil {
		t.Fatal("readZipFile error = nil, want not found error")
	}

	if got := stringFromPlist(map[string]any{"count": 2}, "count"); got != "2" {
		t.Fatalf("stringFromPlist(count) = %q, want %q", got, "2")
	}
	if got := stringFromPlist(map[string]any{}, "missing"); got != "" {
		t.Fatalf("stringFromPlist(missing) = %q, want empty", got)
	}

	perms := extractPermissions(map[string]any{
		"NSCameraUsageDescription": "camera",
		"CFBundleName":             "ignored",
	})
	if len(perms) != 1 || perms[0].RawName != "NSCameraUsageDescription" || perms[0].Source != "info_plist" {
		t.Fatalf("extractPermissions = %#v", perms)
	}

	if got := parseEntitlements([]byte("no plist here")); got != nil {
		t.Fatalf("parseEntitlements(no xml) = %#v, want nil", got)
	}
	invalidEntitlements := mustMarshalPlist(t, map[string]any{"Entitlements": "not-a-map"})
	if got := parseEntitlements(append([]byte("CMS"), invalidEntitlements...)); got != nil {
		t.Fatalf("parseEntitlements(non-map) = %#v, want nil", got)
	}

	iconNames := findIconNames(map[string]any{
		"CFBundleIcons": map[string]any{
			"CFBundlePrimaryIcon": map[string]any{
				"CFBundleIconFiles": []any{"primary"},
			},
		},
		"CFBundleIconFiles": []any{"legacy"},
		"CFBundleIconFile":  "single",
	})
	seen := map[string]bool{}
	for _, name := range iconNames {
		seen[name] = true
	}
	if !seen["primary"] || !seen["legacy"] || !seen["single"] {
		t.Fatalf("findIconNames = %#v", iconNames)
	}

	if got := detectImageFormat("icon.JPG"); got != "jpeg" {
		t.Fatalf("detectImageFormat(JPG) = %q, want jpeg", got)
	}
	if got := detectImageFormat("icon.bin"); got != "" {
		t.Fatalf("detectImageFormat(bin) = %q, want empty", got)
	}
}

func TestExtractProvisioningInfoAndCertFallbacks(t *testing.T) {
	certDER := createCertificateDER(t)
	profile := createProvisioningProfile(t, certDER, map[string]any{
		"aps-environment": "development",
	})

	info, err := ExtractProvisioningInfo(profile)
	if err != nil {
		t.Fatalf("ExtractProvisioningInfo: %v", err)
	}
	if info.TeamID != "TEAM123456" || info.TeamName != "Example Team" {
		t.Fatalf("info = %#v", info)
	}
	if len(info.Certs) != 1 {
		t.Fatalf("cert count = %d, want 1", len(info.Certs))
	}

	if _, err := ExtractProvisioningInfo([]byte("no xml here")); err == nil {
		t.Fatal("ExtractProvisioningInfo(no xml) error = nil")
	}
	if _, err := ExtractProvisioningInfo([]byte("<?xml version=\"1.0\"?><plist>")); err == nil {
		t.Fatal("ExtractProvisioningInfo(unterminated plist) error = nil")
	}

	cert := &x509.Certificate{
		Subject:      pkix.Name{Organization: []string{"Subject Org"}},
		Issuer:       pkix.Name{Organization: []string{"Issuer Org"}},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(3600, 0),
		SerialNumber: big.NewInt(99),
		Raw:          []byte("raw-cert"),
	}
	got := certToResult(cert)
	wantFP := sha256.Sum256(cert.Raw)
	if got.Subject != "Subject Org" || got.Issuer != "Issuer Org" {
		t.Fatalf("certToResult = %#v", got)
	}
	if got.SHA256Fingerprint != fmt.Sprintf("%x", wantFP) {
		t.Fatalf("SHA256Fingerprint = %q, want %q", got.SHA256Fingerprint, fmt.Sprintf("%x", wantFP))
	}
}

func newZipReaderForTest(t *testing.T, files map[string][]byte) *zip.Reader {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("Create(%q): %v", name, err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("Write(%q): %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("Close zip: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	return zr
}

func mustMarshalPlist(t *testing.T, v any) []byte {
	t.Helper()

	data, err := plist.MarshalIndent(v, plist.XMLFormat, "\t")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	return data
}

func createProvisioningProfile(t *testing.T, certDER []byte, entitlements map[string]any) []byte {
	t.Helper()

	provision := map[string]any{
		"TeamIdentifier":        []any{"TEAM123456"},
		"TeamName":              "Example Team",
		"AppIDName":             "Example App",
		"Name":                  "Test Profile",
		"CreationDate":          time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
		"ExpirationDate":        time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC),
		"DeveloperCertificates": []any{certDER},
		"Entitlements":          entitlements,
	}

	return append([]byte("CMS-HEADER"), mustMarshalPlist(t, provision)...)
}

func createCertificateDER(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "Test Developer"},
		Issuer:       pkix.Name{CommonName: "Test Developer"},
		NotBefore:    time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}

func createPNGIcon(t *testing.T) []byte {
	t.Helper()

	img := image.NewRGBA(image.Rect(0, 0, 2, 3))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	img.Set(1, 2, color.RGBA{G: 255, A: 255})

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png.Encode: %v", err)
	}
	return buf.Bytes()
}
