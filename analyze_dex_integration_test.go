package mobilepkg_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"testing"

	"github.com/nao1215/mobilepkg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInspect_DEXFindings verifies that DEX-based findings appear in the
// public InspectResult when inspecting an APK via the public API.
func TestInspect_DEXFindings(t *testing.T) {
	t.Parallel()

	apk := buildTestAPKWithDEX(t, "classes.dex", []string{
		"AKIAIOSFODNN7EXAMPLE",
		"http://insecure.api.example.com/v1",
	})
	r := bytes.NewReader(apk)

	result, err := mobilepkg.Inspect(context.Background(), r, int64(len(apk)))
	require.NoError(t, err)

	var dexCategories []string
	for _, f := range result.Findings {
		if f.Category == "dex_secret" || f.Category == "dex_cleartext" {
			dexCategories = append(dexCategories, f.Category)
		}
	}
	assert.NotEmpty(t, dexCategories, "expected DEX-based findings from Inspect()")
}

// TestInspect_DEXDiagnostics verifies that DEX parse diagnostics propagate
// to the public InspectResult.
func TestInspect_DEXDiagnostics(t *testing.T) {
	t.Parallel()

	apk := buildTestAPKWithDEXBytes(t, "classes.dex", []byte("not a dex file at all"))
	r := bytes.NewReader(apk)

	result, err := mobilepkg.Inspect(context.Background(), r, int64(len(apk)))
	require.NoError(t, err)

	var dexDiags []mobilepkg.Diagnostic
	for _, d := range result.Diagnostics {
		if d.Code == "dex.parse_failed" {
			dexDiags = append(dexDiags, d)
		}
	}
	assert.NotEmpty(t, dexDiags, "expected dex.parse_failed diagnostic to propagate")
}

// TestInspect_DEXArchivePath verifies that findings reference the correct
// DEX file name in multi-dex scenarios.
func TestInspect_DEXArchivePath(t *testing.T) {
	t.Parallel()

	apk := buildTestAPKWithDEX(t, "classes2.dex", []string{
		"AKIAIOSFODNN7EXAMPLE",
	})
	r := bytes.NewReader(apk)

	result, err := mobilepkg.Inspect(context.Background(), r, int64(len(apk)))
	require.NoError(t, err)

	for _, f := range result.Findings {
		if f.Category == "dex_secret" {
			require.NotEmpty(t, f.Evidence)
			assert.Equal(t, "classes2.dex", f.Evidence[0].ArchivePath,
				"finding should reference classes2.dex, not classes.dex")
			return
		}
	}
	t.Fatal("expected dex_secret finding")
}

// TestInspect_RealAPK tests the full pipeline with a real APK if available.
func TestInspect_RealAPK(t *testing.T) {
	t.Parallel()

	apkPath := "testdata/no_commit/AndroGoat.apk"
	if _, err := os.Stat(apkPath); os.IsNotExist(err) {
		t.Skip("test APK not available")
	}

	result, err := mobilepkg.InspectFile(context.Background(), apkPath)
	require.NoError(t, err)

	var dexFindings int
	for _, f := range result.Findings {
		switch f.Category {
		case "dex_secret", "dex_webview", "dex_cleartext", "dex_dangerous_api":
			dexFindings++
		}
	}
	assert.Greater(t, dexFindings, 0, "expected DEX findings from AndroGoat.apk")
}

// TestInspect_RealXAPK tests XAPK DEX scanning with a real file if available.
func TestInspect_RealXAPK(t *testing.T) {
	t.Parallel()

	xapkPath := "testdata/no_commit/Google Chrome_146.0.7680.164_APKPure.xapk"
	if _, err := os.Stat(xapkPath); os.IsNotExist(err) {
		t.Skip("test XAPK not available")
	}

	result, err := mobilepkg.InspectFile(context.Background(), xapkPath)
	require.NoError(t, err)
	assert.Equal(t, mobilepkg.FormatXAPK, result.Format)

	var dexFindings int
	for _, f := range result.Findings {
		switch f.Category {
		case "dex_dangerous_api", "dex_webview", "dex_secret", "dex_cleartext":
			dexFindings++
		}
	}
	assert.Greater(t, dexFindings, 0, "expected DEX findings from XAPK")
}

// buildTestAPKWithDEX creates a minimal APK with a named DEX file.
func buildTestAPKWithDEX(t *testing.T, dexName string, strs []string) []byte {
	t.Helper()
	return buildTestAPKWithDEXBytes(t, dexName, buildMinDEXForTest(t, strs))
}

func buildTestAPKWithDEXBytes(t *testing.T, dexName string, dexData []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	w, err := zw.Create("AndroidManifest.xml")
	require.NoError(t, err)
	_, err = w.Write(buildMinBinaryXMLManifest("com.test.dexscan"))
	require.NoError(t, err)

	w, err = zw.Create(dexName)
	require.NoError(t, err)
	_, err = w.Write(dexData)
	require.NoError(t, err)

	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func buildMinDEXForTest(t *testing.T, strs []string) []byte {
	t.Helper()
	le := binary.LittleEndian
	const hdrSize = 0x70

	hdr := make([]byte, hdrSize)
	stringIDsOff := hdrSize
	stringIDsBytes := make([]byte, len(strs)*4)

	dataOff := stringIDsOff + len(stringIDsBytes)
	var dataBytes []byte
	for i, s := range strs {
		off := dataOff + len(dataBytes)
		le.PutUint32(stringIDsBytes[i*4:], uint32(off))
		dataBytes = appendULEB128ForTest(dataBytes, uint32(len(s)))
		dataBytes = append(dataBytes, []byte(s)...)
		dataBytes = append(dataBytes, 0)
	}

	fileSize := dataOff + len(dataBytes)
	copy(hdr[0:8], "dex\n035\x00")
	le.PutUint32(hdr[32:36], uint32(fileSize))
	le.PutUint32(hdr[36:40], hdrSize)
	le.PutUint32(hdr[40:44], 0x12345678)
	le.PutUint32(hdr[56:60], uint32(len(strs)))
	le.PutUint32(hdr[60:64], uint32(stringIDsOff))
	le.PutUint32(hdr[104:108], uint32(len(dataBytes)))
	le.PutUint32(hdr[108:112], uint32(dataOff))

	out := make([]byte, 0, fileSize)
	out = append(out, hdr...)
	out = append(out, stringIDsBytes...)
	out = append(out, dataBytes...)
	return out
}

func appendULEB128ForTest(buf []byte, v uint32) []byte {
	for {
		b := byte(v & 0x7F)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if v == 0 {
			break
		}
	}
	return buf
}

// TestInspect_XAPKNestedPaths verifies that findings from XAPK splits
// reference the split APK name in the evidence path (e.g. "base.apk!/classes.dex").
func TestInspect_XAPKNestedPaths(t *testing.T) {
	t.Parallel()

	// Build a minimal XAPK: outer ZIP with manifest.json + two inner APKs.
	innerBase := buildTestAPKWithDEX(t, "classes.dex", []string{"AKIAIOSFODNN7EXAMPLE"})
	innerFeature := buildTestAPKWithDEX(t, "classes.dex", []string{"http://insecure.feature.example.com/api"})

	var outer bytes.Buffer
	zw := zip.NewWriter(&outer)

	// manifest.json (minimal XAPK manifest)
	w, err := zw.Create("manifest.json")
	require.NoError(t, err)
	_, err = w.Write([]byte(`{"xapk_version":2,"package_name":"com.test.xapk","name":"Test","version_code":1,"version_name":"1.0"}`))
	require.NoError(t, err)

	w, err = zw.Create("base.apk")
	require.NoError(t, err)
	_, err = w.Write(innerBase)
	require.NoError(t, err)

	w, err = zw.Create("feature_dynamic.apk")
	require.NoError(t, err)
	_, err = w.Write(innerFeature)
	require.NoError(t, err)

	require.NoError(t, zw.Close())

	xapk := outer.Bytes()
	r := bytes.NewReader(xapk)

	result, err := mobilepkg.Inspect(context.Background(), r, int64(len(xapk)))
	require.NoError(t, err)
	assert.Equal(t, mobilepkg.FormatXAPK, result.Format)

	// Verify that findings reference split-qualified paths.
	var paths []string
	for _, f := range result.Findings {
		if len(f.Evidence) > 0 && f.Category == "dex_secret" {
			paths = append(paths, f.Evidence[0].ArchivePath)
		}
	}
	require.NotEmpty(t, paths, "expected dex_secret finding from XAPK")
	assert.Contains(t, paths[0], "base.apk!/", "archive path should include split name")

	var cleartextPaths []string
	for _, f := range result.Findings {
		if len(f.Evidence) > 0 && f.Category == "dex_cleartext" {
			cleartextPaths = append(cleartextPaths, f.Evidence[0].ArchivePath)
		}
	}
	require.NotEmpty(t, cleartextPaths, "expected dex_cleartext from feature split")
	assert.Contains(t, cleartextPaths[0], "feature_dynamic.apk!/", "cleartext should reference feature split")
}

// TestInspect_APKSNestedPaths verifies APKS format DEX scanning across splits.
func TestInspect_APKSNestedPaths(t *testing.T) {
	t.Parallel()

	// Build a minimal APKS: outer ZIP with splits/base-master.apk + splits/feature.apk.
	innerBase := buildTestAPKWithDEX(t, "classes.dex", []string{"AKIAIOSFODNN7EXAMPLE"})
	innerFeature := buildTestAPKWithDEX(t, "classes.dex", []string{"http://insecure.split.example.com/api"})

	var outer bytes.Buffer
	zw := zip.NewWriter(&outer)

	// toc.pb is the marker that makes probeZip detect APKS format.
	w, err := zw.Create("toc.pb")
	require.NoError(t, err)
	_, err = w.Write([]byte{})
	require.NoError(t, err)

	w, err = zw.Create("splits/base-master.apk")
	require.NoError(t, err)
	_, err = w.Write(innerBase)
	require.NoError(t, err)

	w, err = zw.Create("splits/feature-dynamic.apk")
	require.NoError(t, err)
	_, err = w.Write(innerFeature)
	require.NoError(t, err)

	require.NoError(t, zw.Close())

	apks := outer.Bytes()
	r := bytes.NewReader(apks)

	result, err := mobilepkg.Inspect(context.Background(), r, int64(len(apks)))
	require.NoError(t, err)
	assert.Equal(t, mobilepkg.FormatAPKS, result.Format)

	var secretPaths, cleartextPaths []string
	for _, f := range result.Findings {
		if len(f.Evidence) == 0 {
			continue
		}
		switch f.Category {
		case "dex_secret":
			secretPaths = append(secretPaths, f.Evidence[0].ArchivePath)
		case "dex_cleartext":
			cleartextPaths = append(cleartextPaths, f.Evidence[0].ArchivePath)
		}
	}
	require.NotEmpty(t, secretPaths, "expected dex_secret from APKS base split")
	assert.Contains(t, secretPaths[0], "splits/base-master.apk!/")
	require.NotEmpty(t, cleartextPaths, "expected dex_cleartext from APKS feature split")
	assert.Contains(t, cleartextPaths[0], "splits/feature-dynamic.apk!/")
}

// TestInspect_SplitOpenFailedDiagnostic verifies that a corrupt inner APK
// produces a dex.split_open_failed diagnostic.
func TestInspect_SplitOpenFailedDiagnostic(t *testing.T) {
	t.Parallel()

	innerGood := buildTestAPKWithDEX(t, "classes.dex", []string{"normal"})

	var outer bytes.Buffer
	zw := zip.NewWriter(&outer)

	w, err := zw.Create("manifest.json")
	require.NoError(t, err)
	_, err = w.Write([]byte(`{"xapk_version":2,"package_name":"com.test","name":"T","version_code":1,"version_name":"1"}`))
	require.NoError(t, err)

	w, err = zw.Create("base.apk")
	require.NoError(t, err)
	_, err = w.Write(innerGood)
	require.NoError(t, err)

	// Corrupt inner APK.
	w, err = zw.Create("broken.apk")
	require.NoError(t, err)
	_, err = w.Write([]byte("this is not a zip"))
	require.NoError(t, err)

	require.NoError(t, zw.Close())

	xapk := outer.Bytes()
	r := bytes.NewReader(xapk)

	result, err := mobilepkg.Inspect(context.Background(), r, int64(len(xapk)))
	require.NoError(t, err)

	var splitDiags int
	for _, d := range result.Diagnostics {
		if d.Code == "dex.split_open_failed" {
			splitDiags++
			assert.Contains(t, d.Message, "broken.apk")
		}
	}
	assert.Equal(t, 1, splitDiags, "expected exactly one split_open_failed diagnostic for broken.apk")
}
