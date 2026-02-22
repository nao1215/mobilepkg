package mobilepkg_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nao1215/mobilepkg"
)

func TestInspectFile_Signing_UnsignedAPK(t *testing.T) {
	t.Parallel()

	const apkPath = "doc/androidbinary/apk/testdata/helloworld.apk"
	report, err := mobilepkg.InspectFile(context.Background(), apkPath, mobilepkg.InspectOptions{
		Sections: mobilepkg.SectionSigning,
	})
	if err != nil {
		t.Fatalf("InspectFile returned error: %v", err)
	}
	if report.Signing != nil {
		t.Errorf("Signing should be nil for unsigned APK, got scheme=%q", report.Signing.Scheme)
	}
}

func TestInspectFile_Signing_V1SignedAPK(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	apkPath := createV1SignedAPK(t, dir)

	report, err := mobilepkg.InspectFile(context.Background(), apkPath, mobilepkg.InspectOptions{
		Sections: mobilepkg.SectionSigning | mobilepkg.SectionIdentity,
	})
	if err != nil {
		t.Fatalf("InspectFile returned error: %v", err)
	}
	if report.Signing == nil {
		t.Fatal("Signing should not be nil for V1-signed APK")
	}
	if report.Signing.Scheme != "v1" {
		t.Errorf("Scheme = %q, want %q", report.Signing.Scheme, "v1")
	}
	if len(report.Signing.Certificates) == 0 {
		t.Fatal("Certificates should not be empty")
	}

	cert := report.Signing.Certificates[0]
	if cert.Subject == "" {
		t.Error("Subject should not be empty")
	}
	if cert.Issuer == "" {
		t.Error("Issuer should not be empty")
	}
	if cert.SHA256Fingerprint == "" {
		t.Error("SHA256Fingerprint should not be empty")
	}
	if cert.SerialNumber == "" {
		t.Error("SerialNumber should not be empty")
	}
	if cert.NotBefore == "" {
		t.Error("NotBefore should not be empty")
	}
	if cert.NotAfter == "" {
		t.Error("NotAfter should not be empty")
	}
}

func TestInspectFile_Signing_IOSWithProvision(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ipaPath := createIPAWithProvision(t, dir)

	report, err := mobilepkg.InspectFile(context.Background(), ipaPath, mobilepkg.InspectOptions{
		Sections: mobilepkg.SectionSigning,
	})
	if err != nil {
		t.Fatalf("InspectFile returned error: %v", err)
	}
	if report.Signing == nil {
		t.Fatal("Signing should not be nil for IPA with provisioning profile")
	}
	if report.Signing.Scheme != "apple" {
		t.Errorf("Scheme = %q, want %q", report.Signing.Scheme, "apple")
	}
	if len(report.Signing.Certificates) == 0 {
		t.Fatal("Certificates should not be empty")
	}

	cert := report.Signing.Certificates[0]
	if cert.Subject != "Test Developer" {
		t.Errorf("Subject = %q, want %q", cert.Subject, "Test Developer")
	}
}

func TestInspectFile_Signing_IOSWithoutProvision(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ipaPath := createTestIPA(t, dir)

	report, err := mobilepkg.InspectFile(context.Background(), ipaPath, mobilepkg.InspectOptions{
		Sections: mobilepkg.SectionSigning,
	})
	if err != nil {
		t.Fatalf("InspectFile returned error: %v", err)
	}
	if report.Signing != nil {
		t.Errorf("Signing should be nil for IPA without provisioning profile")
	}
}

func TestInspectFile_Signing_V1MultiCert(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	apkPath := createV1SignedAPKMultiCert(t, dir)

	report, err := mobilepkg.InspectFile(context.Background(), apkPath, mobilepkg.InspectOptions{
		Sections: mobilepkg.SectionSigning | mobilepkg.SectionIdentity,
	})
	if err != nil {
		t.Fatalf("InspectFile returned error: %v", err)
	}
	if report.Signing == nil {
		t.Fatal("Signing should not be nil for multi-cert APK")
	}
	if len(report.Signing.Certificates) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(report.Signing.Certificates))
	}
	// Verify both certs are distinct
	if report.Signing.Certificates[0].SHA256Fingerprint == report.Signing.Certificates[1].SHA256Fingerprint {
		t.Error("certificates should have distinct fingerprints")
	}
}

// --- helpers ---

// generateTestCert creates a self-signed X.509 certificate and private key for testing.
func generateTestCert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Developer",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	return cert, key, certDER
}

// buildPKCS7SignedData creates a minimal PKCS#7 SignedData blob containing the certificate.
// We build the DER manually to ensure correct implicit tagging for the certificates field.
func buildPKCS7SignedData(t *testing.T, certDER []byte) []byte {
	t.Helper()

	// Helper to build a DER TLV (tag, length, value).
	tlv := func(tag byte, content []byte) []byte {
		var b bytes.Buffer
		b.WriteByte(tag)
		l := len(content)
		if l < 128 {
			b.WriteByte(byte(l))
		} else if l < 256 {
			b.WriteByte(0x81)
			b.WriteByte(byte(l))
		} else {
			b.WriteByte(0x82)
			b.WriteByte(byte(l >> 8))
			b.WriteByte(byte(l))
		}
		b.Write(content)
		return b.Bytes()
	}

	// SignedData OID: 1.2.840.113549.1.7.2
	signedDataOID, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2})
	// Data OID: 1.2.840.113549.1.7.1
	dataOID, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1})

	version, _ := asn1.Marshal(1)
	digestAlgs := tlv(0x31, nil)                  // SET (empty)
	encapContent := tlv(0x30, dataOID)             // SEQUENCE { contentType }
	certificates := tlv(0xa0, certDER)             // [0] IMPLICIT constructed

	// SignedData SEQUENCE
	var sdContent bytes.Buffer
	sdContent.Write(version)
	sdContent.Write(digestAlgs)
	sdContent.Write(encapContent)
	sdContent.Write(certificates)
	signedData := tlv(0x30, sdContent.Bytes())

	// ContentInfo SEQUENCE { contentType, content [0] EXPLICIT }
	explicitContent := tlv(0xa0, signedData)
	var ciContent bytes.Buffer
	ciContent.Write(signedDataOID)
	ciContent.Write(explicitContent)

	return tlv(0x30, ciContent.Bytes())
}

// createV1SignedAPK builds a fake APK with a META-INF/CERT.RSA file
// containing a PKCS#7 SignedData blob with a test certificate.
func createV1SignedAPK(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "v1signed.apk")

	_, _, certDER := generateTestCert(t)
	pkcs7 := buildPKCS7SignedData(t, certDER)

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	// Copy entries from real APK to get a valid binary AndroidManifest.xml
	realAPK, err := os.ReadFile("doc/androidbinary/apk/testdata/helloworld.apk")
	if err != nil {
		t.Fatal(err)
	}
	realZR, err := zip.NewReader(bytes.NewReader(realAPK), int64(len(realAPK)))
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range realZR.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		fw, err := w.Create(f.Name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(data); err != nil {
			t.Fatal(err)
		}
	}

	// Add V1 signing files
	fw, err := w.Create("META-INF/CERT.RSA")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(pkcs7); err != nil {
		t.Fatal(err)
	}

	fw, err = w.Create("META-INF/CERT.SF")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte("Signature-Version: 1.0\n")); err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// generateTestCertWithSerial creates a self-signed X.509 cert with the given serial and CN.
func generateTestCertWithSerial(t *testing.T, serial int64, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return certDER
}

// createV1SignedAPKMultiCert builds a fake APK with a META-INF/CERT.RSA
// containing a PKCS#7 SignedData blob with two distinct certificates.
func createV1SignedAPKMultiCert(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "v1multi.apk")

	cert1DER := generateTestCertWithSerial(t, 1, "Developer One")
	cert2DER := generateTestCertWithSerial(t, 2, "Developer Two")

	// Concatenate both cert DERs for the PKCS#7 certificates field.
	combinedCerts := append(cert1DER, cert2DER...)
	pkcs7 := buildPKCS7SignedData(t, combinedCerts)

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	realAPK, err := os.ReadFile("doc/androidbinary/apk/testdata/helloworld.apk")
	if err != nil {
		t.Fatal(err)
	}
	realZR, err := zip.NewReader(bytes.NewReader(realAPK), int64(len(realAPK)))
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range realZR.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		fw, err := w.Create(f.Name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(data); err != nil {
			t.Fatal(err)
		}
	}

	fw, err := w.Create("META-INF/CERT.RSA")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(pkcs7); err != nil {
		t.Fatal(err)
	}

	fw, err = w.Create("META-INF/CERT.SF")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte("Signature-Version: 1.0\n")); err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// createIPAWithProvision builds a fake IPA with an embedded.mobileprovision file.
func createIPAWithProvision(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "provisioned.ipa")

	_, _, certDER := generateTestCert(t)

	provPlist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>TeamIdentifier</key>
	<array><string>ABCDE12345</string></array>
	<key>TeamName</key>
	<string>Test Team</string>
	<key>Name</key>
	<string>Test Profile</string>
	<key>AppIDName</key>
	<string>TestApp</string>
	<key>CreationDate</key>
	<date>2024-01-01T00:00:00Z</date>
	<key>ExpirationDate</key>
	<date>2025-01-01T00:00:00Z</date>
	<key>DeveloperCertificates</key>
	<array><data>%s</data></array>
	<key>Entitlements</key>
	<dict>
		<key>com.apple.developer.team-identifier</key>
		<string>ABCDE12345</string>
		<key>application-identifier</key>
		<string>ABCDE12345.com.example.testapp</string>
	</dict>
</dict>
</plist>`, base64.StdEncoding.EncodeToString(certDER))

	// Fake CMS wrapper: just prefix binary junk before the XML plist.
	provData := append([]byte{0x30, 0x82, 0x00, 0x00}, []byte(provPlist)...)

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	infoPlist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>com.example.testapp</string>
	<key>CFBundleDisplayName</key>
	<string>Test App</string>
	<key>CFBundleShortVersionString</key>
	<string>1.0</string>
	<key>CFBundleVersion</key>
	<string>1</string>
	<key>CFBundleExecutable</key>
	<string>TestApp</string>
</dict>
</plist>`

	fw, err := w.Create("Payload/TestApp.app/Info.plist")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte(infoPlist)); err != nil {
		t.Fatal(err)
	}

	fw, err = w.Create("Payload/TestApp.app/embedded.mobileprovision")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(provData); err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
