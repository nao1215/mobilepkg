package android

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/izinga/aab-parser/pb"
	"google.golang.org/protobuf/proto"
)

func TestParseNetworkSecurityConfig_BinaryXML(t *testing.T) {
	const apkPath = "../../../testdata/android/androgoat_rich.apk"

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

func TestInspectAAB_AllSections(t *testing.T) {
	data := createTestAABArchive(t)

	result, diags, err := InspectAAB(bytes.NewReader(data), int64(len(data)), 0x7F, 96, 1<<20)
	if err != nil {
		t.Fatalf("InspectAAB: %v", err)
	}

	if result.PackageName != "com.example.aabtest" {
		t.Fatalf("PackageName = %q, want %q", result.PackageName, "com.example.aabtest")
	}
	if result.Label != "AAB Test App" {
		t.Fatalf("Label = %q, want %q", result.Label, "AAB Test App")
	}
	if result.VersionName != "3.0.0" || result.VersionCode != "10" {
		t.Fatalf("version = %q/%q, want %q/%q", result.VersionName, result.VersionCode, "3.0.0", "10")
	}
	if result.MainActivity != "com.example.aabtest.MainActivity" {
		t.Fatalf("MainActivity = %q, want %q", result.MainActivity, "com.example.aabtest.MainActivity")
	}
	if len(result.Permissions) != 2 {
		t.Fatalf("Permissions len = %d, want 2", len(result.Permissions))
	}
	if result.MinSDK != "21" || result.TargetSDK != "34" {
		t.Fatalf("SDK = %q/%q, want %q/%q", result.MinSDK, result.TargetSDK, "21", "34")
	}
	if got := result.RawManifest["package"]; got != "com.example.aabtest" {
		t.Fatalf("RawManifest[package] = %#v, want %q", got, "com.example.aabtest")
	}

	foundIconDiag := false
	for _, d := range diags {
		if d.Code == "icon.not_found" {
			foundIconDiag = true
		}
	}
	if !foundIconDiag {
		t.Fatalf("expected icon.not_found diagnostic, got %#v", diags)
	}
}

func TestInspectXAPK_FallbackAndMerge(t *testing.T) {
	innerAPK := createPlainTextAPKArchive(t)
	manifestJSON, err := json.Marshal(map[string]any{
		"xapk_version": 2,
		"package_name": "com.example.xapk",
		"name":         "XAPK Test App",
		"version_code": 42,
		"version_name": "1.2.3",
		"permissions":  []string{"android.permission.CAMERA"},
		"split_apks":   []map[string]string{{"file": "base.apk", "id": "base"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	zr := newZipReaderForTest(t, map[string][]byte{
		"manifest.json": manifestJSON,
		"base.apk":      innerAPK,
	})

	result, diags, err := InspectXAPK(zr, (1<<0)|(1<<1)|(1<<3)|(1<<5), 1<<20, nil)
	if err != nil {
		t.Fatalf("InspectXAPK: %v", err)
	}
	// The inner APK in this test has a plain-text manifest (not binary XML),
	// so parsing fails and we fall back to manifest.json. The fallback now
	// emits a diagnostic instead of silently succeeding.
	if len(diags) != 1 || diags[0].Code != "xapk.base_apk_parse_failed" {
		t.Fatalf("diags = %#v, want single xapk.base_apk_parse_failed diagnostic", diags)
	}
	if result.PackageName != "com.example.xapk" || result.Label != "XAPK Test App" {
		t.Fatalf("identity = %q/%q", result.PackageName, result.Label)
	}
	if result.VersionCode != "42" || result.VersionName != "1.2.3" {
		t.Fatalf("version = %q/%q", result.VersionCode, result.VersionName)
	}
	if len(result.Permissions) != 1 || result.Permissions[0] != "android.permission.CAMERA" {
		t.Fatalf("permissions = %#v", result.Permissions)
	}
	if got := result.RawManifest["package"]; got != "com.example.xapk" {
		t.Fatalf("RawManifest[package] = %#v, want %q", got, "com.example.xapk")
	}

	base := &Result{}
	mergeXAPKMetadata(base, xapkManifest{
		PackageName: "com.example.merge",
		Name:        "Merged",
		VersionCode: 7,
		VersionName: "7.0.0",
		Permissions: []string{"android.permission.INTERNET"},
	}, (1<<0)|(1<<1)|(1<<3))
	if base.PackageName != "com.example.merge" || base.Label != "Merged" {
		t.Fatalf("merged identity = %#v", base)
	}
	if base.VersionCode != "7" || base.VersionName != "7.0.0" {
		t.Fatalf("merged version = %#v", base)
	}
	if len(base.Permissions) != 1 || base.Permissions[0] != "android.permission.INTERNET" {
		t.Fatalf("merged permissions = %#v", base.Permissions)
	}

	keep := &Result{
		PackageName: "keep.id",
		Label:       "Keep",
		VersionCode: "9",
		VersionName: "9.0.0",
		Permissions: []string{"existing"},
	}
	mergeXAPKMetadata(keep, xapkManifest{
		PackageName: "ignored.id",
		Name:        "Ignored",
		VersionCode: 1,
		VersionName: "1.0.0",
		Permissions: []string{"ignored"},
	}, (1<<0)|(1<<1)|(1<<3))
	if keep.PackageName != "keep.id" || keep.Label != "Keep" {
		t.Fatalf("merge overwrote identity: %#v", keep)
	}
	if keep.VersionCode != "9" || keep.VersionName != "9.0.0" {
		t.Fatalf("merge overwrote version: %#v", keep)
	}
	if len(keep.Permissions) != 1 || keep.Permissions[0] != "existing" {
		t.Fatalf("merge overwrote permissions: %#v", keep.Permissions)
	}
}

func TestInspectAPKSAndNestedZip(t *testing.T) {
	innerAPK := createPlainTextAPKArchive(t)

	t.Run("base-master is found and inspect propagates parse error", func(t *testing.T) {
		zr := newZipReaderForTest(t, map[string][]byte{
			"splits/base-master.apk": innerAPK,
		})

		inner, err := findBaseMasterAPK(zr, 1<<20, nil)
		if err != nil {
			t.Fatalf("findBaseMasterAPK: %v", err)
		}
		if len(inner.File) == 0 {
			t.Fatal("inner archive is empty")
		}

		if _, _, err := InspectAPKS(zr, 0xFF, 1<<20, nil); err == nil {
			t.Fatal("InspectAPKS error = nil, want parse error from inner APK")
		}
	})

	t.Run("universal fallback works", func(t *testing.T) {
		zr := newZipReaderForTest(t, map[string][]byte{
			"universal.apk": innerAPK,
		})

		if _, err := findBaseMasterAPK(zr, 1<<20, nil); err != nil {
			t.Fatalf("findBaseMasterAPK(universal): %v", err)
		}
	})

	t.Run("openNestedZip rejects invalid inner zip", func(t *testing.T) {
		zr := newZipReaderForTest(t, map[string][]byte{
			"base.apk": []byte("not a zip"),
		})

		if _, err := openNestedZip(zr, "base.apk", 1<<20); err == nil {
			t.Fatal("openNestedZip error = nil, want invalid zip error")
		}
	})

	t.Run("findNestedAPK returns error when nothing matches", func(t *testing.T) {
		zr := newZipReaderForTest(t, map[string][]byte{
			"base.apk": innerAPK,
		})

		if _, err := findNestedAPK(zr, []string{"missing.apk"}, 1<<20, nil); err == nil {
			t.Fatal("findNestedAPK error = nil, want not found error")
		}
	})
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

func createPlainTextAPKArchive(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?><manifest package="com.example.bad"/>`)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func createTestAABArchive(t *testing.T) []byte {
	t.Helper()

	node := &pb.XmlNode{
		Node: &pb.XmlNode_Element{
			Element: &pb.XmlElement{
				Name: "manifest",
				Attribute: []*pb.XmlAttribute{
					{Name: "package", Value: "com.example.aabtest"},
					{Name: "versionCode", Value: "10"},
					{Name: "versionName", Value: "3.0.0"},
				},
				Child: []*pb.XmlNode{
					{
						Node: &pb.XmlNode_Element{
							Element: &pb.XmlElement{
								Name: "uses-permission",
								Attribute: []*pb.XmlAttribute{
									{Name: "name", Value: "android.permission.CAMERA"},
								},
							},
						},
					},
					{
						Node: &pb.XmlNode_Element{
							Element: &pb.XmlElement{
								Name: "uses-permission",
								Attribute: []*pb.XmlAttribute{
									{Name: "name", Value: "android.permission.INTERNET"},
								},
							},
						},
					},
					{
						Node: &pb.XmlNode_Element{
							Element: &pb.XmlElement{
								Name: "uses-sdk",
								Attribute: []*pb.XmlAttribute{
									{Name: "minSdkVersion", Value: "21"},
									{Name: "targetSdkVersion", Value: "34"},
								},
							},
						},
					},
					{
						Node: &pb.XmlNode_Element{
							Element: &pb.XmlElement{
								Name: "application",
								Attribute: []*pb.XmlAttribute{
									{Name: "label", Value: "AAB Test App"},
								},
								Child: []*pb.XmlNode{
									{
										Node: &pb.XmlNode_Element{
											Element: &pb.XmlElement{
												Name: "activity",
												Attribute: []*pb.XmlAttribute{
													{Name: "name", Value: "com.example.aabtest.MainActivity"},
												},
												Child: []*pb.XmlNode{
													{
														Node: &pb.XmlNode_Element{
															Element: &pb.XmlElement{
																Name: "intent-filter",
																Child: []*pb.XmlNode{
																	{
																		Node: &pb.XmlNode_Element{
																			Element: &pb.XmlElement{
																				Name: "action",
																				Attribute: []*pb.XmlAttribute{
																					{Name: "name", Value: "android.intent.action.MAIN"},
																				},
																			},
																		},
																	},
																	{
																		Node: &pb.XmlNode_Element{
																			Element: &pb.XmlElement{
																				Name: "category",
																				Attribute: []*pb.XmlAttribute{
																					{Name: "name", Value: "android.intent.category.LAUNCHER"},
																				},
																			},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	manifestData, err := proto.Marshal(node)
	if err != nil {
		t.Fatal(err)
	}
	resData, err := proto.Marshal(&pb.ResourceTable{})
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := map[string][]byte{
		"BundleConfig.pb":                   {0x00},
		"base/manifest/AndroidManifest.xml": manifestData,
		"base/resources.pb":                 resData,
	}
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
		t.Fatal(err)
	}
	return buf.Bytes()
}
