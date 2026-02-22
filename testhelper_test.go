package mobilepkg_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/izinga/aab-parser/pb"
	"google.golang.org/protobuf/proto"
	"howett.net/plist"
)

// createTestAPK builds a minimal fake APK file at the given path.
// The APK contains a text-format AndroidManifest.xml (not binary XML)
// which is sufficient for testing the probe layer but not the full
// Android binary XML parser. For full integration tests, use a real APK.
func createTestAPK(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "test.apk")

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	manifestXML := `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.testapp"
    android:versionCode="42"
    android:versionName="1.2.3">
    <uses-permission android:name="android.permission.CAMERA"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <application android:label="TestApp" android:icon="res/mipmap/ic_launcher.png">
        <activity android:name="com.example.testapp.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="34"/>
</manifest>`

	f, err := w.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(manifestXML)); err != nil {
		t.Fatal(err)
	}

	f, err = w.Create("resources.arsc")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{}); err != nil {
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

// createTestIPA builds a minimal fake IPA file at the given path.
func createTestIPA(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "test.ipa")

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	infoPlist := map[string]any{
		"CFBundleIdentifier":                  "com.example.testapp",
		"CFBundleDisplayName":                 "Test App",
		"CFBundleShortVersionString":          "2.0.1",
		"CFBundleVersion":                     "100",
		"CFBundleExecutable":                  "TestApp",
		"NSCameraUsageDescription":            "We need camera access",
		"NSLocationWhenInUseUsageDescription": "We need location access",
	}

	plistData, err := plist.MarshalIndent(infoPlist, plist.XMLFormat, "\t")
	if err != nil {
		t.Fatal(err)
	}

	f, err := w.Create("Payload/TestApp.app/Info.plist")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(plistData); err != nil {
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

// createTestIPAWithMinOS builds a fake IPA with MinimumOSVersion set.
func createTestIPAWithMinOS(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "test_minos.ipa")

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	infoPlist := map[string]any{
		"CFBundleIdentifier":         "com.example.testapp",
		"CFBundleDisplayName":        "Test App",
		"CFBundleShortVersionString": "2.0.1",
		"CFBundleVersion":            "100",
		"CFBundleExecutable":         "TestApp",
		"MinimumOSVersion":           "15.0",
	}

	plistData, err := plist.MarshalIndent(infoPlist, plist.XMLFormat, "\t")
	if err != nil {
		t.Fatal(err)
	}

	f, err := w.Create("Payload/TestApp.app/Info.plist")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(plistData); err != nil {
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

// createTestAABWithSDK builds a fake AAB with uses-sdk element in the protobuf manifest.
func createTestAABWithSDK(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "test_sdk.aab")

	node := &pb.XmlNode{
		Node: &pb.XmlNode_Element{
			Element: &pb.XmlElement{
				Name: "manifest",
				Attribute: []*pb.XmlAttribute{
					{Name: "package", Value: "com.example.sdktest"},
					{Name: "versionCode", Value: "1"},
					{Name: "versionName", Value: "1.0.0"},
				},
				Child: []*pb.XmlNode{
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

	resTable := &pb.ResourceTable{}
	resData, err := proto.Marshal(resTable)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	f, err := w.Create("BundleConfig.pb")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0x00}); err != nil {
		t.Fatal(err)
	}

	f, err = w.Create("base/manifest/AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(manifestData); err != nil {
		t.Fatal(err)
	}

	f, err = w.Create("base/resources.pb")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(resData); err != nil {
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

// createEmptyZip builds a valid ZIP archive with no entries.
func createEmptyZip(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "empty.zip")

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// createTestXAPK builds a minimal fake XAPK file containing manifest.json
// and the real helloworld.apk as the base APK.
func createTestXAPK(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "test.xapk")

	// Read the real APK to embed inside the XAPK
	realAPK, err := os.ReadFile("doc/androidbinary/apk/testdata/helloworld.apk")
	if err != nil {
		t.Fatal(err)
	}

	manifest := map[string]any{
		"xapk_version": 2,
		"package_name": "com.example.helloworld",
		"name":         "HelloWorld",
		"version_code": "1",
		"version_name": "1.0",
		"permissions":  []string{"android.permission.INTERNET"},
		"split_apks": []map[string]string{
			{"file": "base.apk", "id": "base"},
		},
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	f, err := w.Create("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(manifestJSON); err != nil {
		t.Fatal(err)
	}

	f, err = w.Create("base.apk")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(realAPK); err != nil {
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

// createTestAPKS builds a minimal fake APKS file containing a toc.pb
// and the real helloworld.apk as splits/base-master.apk.
func createTestAPKS(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "test.apks")

	realAPK, err := os.ReadFile("doc/androidbinary/apk/testdata/helloworld.apk")
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	// Dummy toc.pb (just needs to exist for probe detection)
	f, err := w.Create("toc.pb")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0x00}); err != nil {
		t.Fatal(err)
	}

	f, err = w.Create("splits/base-master.apk")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(realAPK); err != nil {
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

// createTestAAB builds a minimal fake AAB file with a protobuf-encoded
// AndroidManifest.xml and BundleConfig.pb.
func createTestAAB(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "test.aab")

	// Build a protobuf manifest
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
								Name: "application",
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
																	{Node: &pb.XmlNode_Element{Element: &pb.XmlElement{
																		Name:      "action",
																		Attribute: []*pb.XmlAttribute{{Name: "name", Value: "android.intent.action.MAIN"}},
																	}}},
																	{Node: &pb.XmlNode_Element{Element: &pb.XmlElement{
																		Name:      "category",
																		Attribute: []*pb.XmlAttribute{{Name: "name", Value: "android.intent.category.LAUNCHER"}},
																	}}},
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

	// Build an empty ResourceTable so parseResources doesn't fail
	resTable := &pb.ResourceTable{}
	resData, err := proto.Marshal(resTable)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	f, err := w.Create("BundleConfig.pb")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0x00}); err != nil {
		t.Fatal(err)
	}

	f, err = w.Create("base/manifest/AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(manifestData); err != nil {
		t.Fatal(err)
	}

	f, err = w.Create("base/resources.pb")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(resData); err != nil {
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
