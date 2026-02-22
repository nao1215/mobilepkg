package android

import (
	"archive/zip"
	"bytes"
	"os"
	"testing"
)

func TestParseNetworkSecurityConfig_BinaryXML(t *testing.T) {
	const apkPath = "../../../testdata/no_commit/AndroGoat.apk"
	if _, err := os.Stat(apkPath); os.IsNotExist(err) {
		t.Skip("test data not available")
	}

	f, err := os.Open(apkPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}

	zr, err := zip.NewReader(f, fi.Size())
	if err != nil {
		t.Fatal(err)
	}

	// Test scanForNSCFile.
	path := scanForNSCFile(zr)
	if path == "" {
		t.Fatal("scanForNSCFile returned empty")
	}
	t.Logf("scanForNSCFile found: %s", path)

	// Test full parseNetworkSecurityConfig with resource ID reference.
	policy := parseNetworkSecurityConfig(zr, "@0x7F130000", 0)
	if policy == nil {
		t.Fatal("parseNetworkSecurityConfig returned nil for resource ID ref")
	}
	t.Logf("NSC Policy: cleartext=%v domains=%d pin=%v trust=%v",
		policy.CleartextPermitted, len(policy.DomainConfigs), policy.HasPinSet, policy.TrustAnchors)

	if !policy.CleartextPermitted {
		t.Error("expected cleartext to be permitted")
	}
	if len(policy.TrustAnchors) == 0 {
		t.Error("expected trust anchors")
	}

	// Also test full Inspect to verify end-to-end propagation.
	result, _, err := Inspect(zr, 0xFF, f, fi.Size(), 0)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if result.NSCPolicy == nil {
		t.Fatal("Inspect result NSCPolicy is nil — propagation failed")
	}
	t.Logf("Inspect NSCPolicy: cleartext=%v domains=%d",
		result.NSCPolicy.CleartextPermitted, len(result.NSCPolicy.DomainConfigs))
}

func TestTryDecodeBinaryXML_PlainXML(t *testing.T) {
	input := []byte(`<?xml version="1.0"?><network-security-config/>`)
	output := tryDecodeBinaryXML(input)
	if !bytes.Equal(input, output) {
		t.Error("plain XML should pass through unchanged")
	}
}
