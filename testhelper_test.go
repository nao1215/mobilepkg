package mobilepkg_test

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
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
// and a synthetic (non-binary-XML) base APK. The inner APK cannot be fully
// parsed by the binary XML parser, so the XAPK inspector falls back to
// manifest.json metadata extraction.
func createTestXAPK(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "test.xapk")

	// Build a synthetic inner APK (text-XML manifest -- not parseable by binary XML parser)
	innerAPKPath := createTestAPK(t, dir)
	innerAPK, err := os.ReadFile(innerAPKPath)
	if err != nil {
		t.Fatal(err)
	}

	manifest := map[string]any{
		"xapk_version": 2,
		"package_name": "com.example.xapktest",
		"name":         "XAPK Test App",
		"version_code": "42",
		"version_name": "1.2.3",
		"permissions":  []string{"android.permission.INTERNET", "android.permission.CAMERA"},
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
	if _, err := f.Write(innerAPK); err != nil {
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
// and a synthetic base APK. The inner APK uses text-XML which the binary
// parser cannot handle, so inspect tests should expect an error.
func createTestAPKS(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "test.apks")

	// Build a synthetic inner APK (text-XML manifest)
	innerAPKPath := createTestAPK(t, dir)
	innerAPK, err := os.ReadFile(innerAPKPath)
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
	if _, err := f.Write(innerAPK); err != nil {
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

// --- Binary XML manifest builder ---
// These helpers produce a minimal binary-format AndroidManifest.xml that
// the APK binary XML parser can handle. They are used by signing tests.

// buildMinBinaryXMLManifest creates a minimal binary-format AndroidManifest.xml
// that can be parsed by the APK binary XML parser.
func buildMinBinaryXMLManifest(packageName string) []byte {
	poolStrings := []string{
		"", // 0
		"http://schemas.android.com/apk/res/android", // 1
		"android",     // 2
		"package",     // 3
		"manifest",    // 4
		packageName,   // 5
		"application", // 6
		"label",       // 7
		"App",         // 8
	}

	pool := buildBinaryStringPool(poolStrings)

	var xmlChunks bytes.Buffer
	writeBinaryStartNS(&xmlChunks, 2, 1)
	writeBinaryStartElement(&xmlChunks, 4, 0xFFFFFFFF, []binaryXMLAttr{
		{ns: 0xFFFFFFFF, name: 3, rawValue: 5},
	})
	writeBinaryStartElement(&xmlChunks, 6, 0xFFFFFFFF, []binaryXMLAttr{
		{ns: 1, name: 7, rawValue: 8},
	})
	writeBinaryEndElement(&xmlChunks, 6, 0xFFFFFFFF)
	writeBinaryEndElement(&xmlChunks, 4, 0xFFFFFFFF)
	writeBinaryEndNS(&xmlChunks, 2, 1)

	var result bytes.Buffer
	totalSize := uint32(8) + uint32(pool.Len()) + uint32(xmlChunks.Len())
	binary.Write(&result, binary.LittleEndian, uint16(0x0003)) // ResXMLTree type
	binary.Write(&result, binary.LittleEndian, uint16(8))      // headerSize
	binary.Write(&result, binary.LittleEndian, totalSize)
	result.Write(pool.Bytes())
	result.Write(xmlChunks.Bytes())

	return result.Bytes()
}

// binaryXMLAttr is an attribute for the binary XML builder.
type binaryXMLAttr struct {
	ns, name, rawValue uint32
}

func buildBinaryStringPool(strs []string) bytes.Buffer {
	var pool bytes.Buffer
	strCount := uint32(len(strs))
	offsets := make([]uint32, strCount)
	var stringsData bytes.Buffer

	for i, s := range strs {
		offsets[i] = uint32(stringsData.Len())
		sRunes := []rune(s)
		binary.Write(&stringsData, binary.LittleEndian, uint16(len(sRunes)))
		for _, r := range sRunes {
			binary.Write(&stringsData, binary.LittleEndian, uint16(r))
		}
		binary.Write(&stringsData, binary.LittleEndian, uint16(0))
	}

	headerSize := uint16(28)
	stringStart := uint32(headerSize) + 4*strCount
	poolSize := uint32(headerSize) + 4*strCount + uint32(stringsData.Len())

	binary.Write(&pool, binary.LittleEndian, uint16(0x0001)) // type
	binary.Write(&pool, binary.LittleEndian, headerSize)
	binary.Write(&pool, binary.LittleEndian, poolSize)
	binary.Write(&pool, binary.LittleEndian, strCount)
	binary.Write(&pool, binary.LittleEndian, uint32(0)) // styleCount
	binary.Write(&pool, binary.LittleEndian, uint32(0)) // flags (UTF-16)
	binary.Write(&pool, binary.LittleEndian, stringStart)
	binary.Write(&pool, binary.LittleEndian, uint32(0)) // stylesStart

	for _, off := range offsets {
		binary.Write(&pool, binary.LittleEndian, off)
	}
	pool.Write(stringsData.Bytes())

	return pool
}

func writeBinaryStartNS(w *bytes.Buffer, prefix, uri uint32) {
	var chunk bytes.Buffer
	binary.Write(&chunk, binary.LittleEndian, uint16(0x0100))
	binary.Write(&chunk, binary.LittleEndian, uint16(16))
	binary.Write(&chunk, binary.LittleEndian, uint32(0)) // placeholder
	binary.Write(&chunk, binary.LittleEndian, uint32(0))
	binary.Write(&chunk, binary.LittleEndian, uint32(0xFFFFFFFF))
	binary.Write(&chunk, binary.LittleEndian, prefix)
	binary.Write(&chunk, binary.LittleEndian, uri)
	data := chunk.Bytes()
	binary.LittleEndian.PutUint32(data[4:8], uint32(len(data)))
	w.Write(data)
}

func writeBinaryEndNS(w *bytes.Buffer, prefix, uri uint32) {
	var chunk bytes.Buffer
	binary.Write(&chunk, binary.LittleEndian, uint16(0x0101))
	binary.Write(&chunk, binary.LittleEndian, uint16(16))
	binary.Write(&chunk, binary.LittleEndian, uint32(0))
	binary.Write(&chunk, binary.LittleEndian, uint32(0))
	binary.Write(&chunk, binary.LittleEndian, uint32(0xFFFFFFFF))
	binary.Write(&chunk, binary.LittleEndian, prefix)
	binary.Write(&chunk, binary.LittleEndian, uri)
	data := chunk.Bytes()
	binary.LittleEndian.PutUint32(data[4:8], uint32(len(data)))
	w.Write(data)
}

func writeBinaryStartElement(w *bytes.Buffer, name, ns uint32, attrs []binaryXMLAttr) {
	var chunk bytes.Buffer
	binary.Write(&chunk, binary.LittleEndian, uint16(0x0102))
	binary.Write(&chunk, binary.LittleEndian, uint16(16))
	binary.Write(&chunk, binary.LittleEndian, uint32(0)) // placeholder
	binary.Write(&chunk, binary.LittleEndian, uint32(0))
	binary.Write(&chunk, binary.LittleEndian, uint32(0xFFFFFFFF))
	// attrExt
	binary.Write(&chunk, binary.LittleEndian, ns)
	binary.Write(&chunk, binary.LittleEndian, name)
	binary.Write(&chunk, binary.LittleEndian, uint16(20))         // attributeStart
	binary.Write(&chunk, binary.LittleEndian, uint16(20))         // attributeSize
	binary.Write(&chunk, binary.LittleEndian, uint16(len(attrs))) // attributeCount
	binary.Write(&chunk, binary.LittleEndian, uint16(0))          // idIndex
	binary.Write(&chunk, binary.LittleEndian, uint16(0))          // classIndex
	binary.Write(&chunk, binary.LittleEndian, uint16(0))          // styleIndex
	for _, a := range attrs {
		binary.Write(&chunk, binary.LittleEndian, a.ns)
		binary.Write(&chunk, binary.LittleEndian, a.name)
		binary.Write(&chunk, binary.LittleEndian, a.rawValue)
		binary.Write(&chunk, binary.LittleEndian, uint16(8)) // TypedValue.Size
		binary.Write(&chunk, binary.LittleEndian, uint8(0))  // res0
		binary.Write(&chunk, binary.LittleEndian, uint8(3))  // dataType=TYPE_STRING
		binary.Write(&chunk, binary.LittleEndian, a.rawValue)
	}
	data := chunk.Bytes()
	binary.LittleEndian.PutUint32(data[4:8], uint32(len(data)))
	w.Write(data)
}

func writeBinaryEndElement(w *bytes.Buffer, name, ns uint32) {
	var chunk bytes.Buffer
	binary.Write(&chunk, binary.LittleEndian, uint16(0x0103))
	binary.Write(&chunk, binary.LittleEndian, uint16(16))
	binary.Write(&chunk, binary.LittleEndian, uint32(0))
	binary.Write(&chunk, binary.LittleEndian, uint32(0))
	binary.Write(&chunk, binary.LittleEndian, uint32(0xFFFFFFFF))
	binary.Write(&chunk, binary.LittleEndian, ns)
	binary.Write(&chunk, binary.LittleEndian, name)
	data := chunk.Bytes()
	binary.LittleEndian.PutUint32(data[4:8], uint32(len(data)))
	w.Write(data)
}
