package android

import (
	"archive/zip"
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeInnerAPKWithDEX creates a minimal valid ZIP containing a dummy
// classes.dex entry so that containsDEX returns true.
func makeInnerAPKWithDEX(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create("classes.dex")
	require.NoError(t, err)
	_, err = f.Write([]byte("dex\n035\x00")) // minimal magic, not a real DEX
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

// makeInnerAPKNoDEX creates a minimal valid ZIP with no DEX entries.
func makeInnerAPKNoDEX(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create("resources.arsc")
	require.NoError(t, err)
	_, err = f.Write([]byte("dummy"))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

func TestOpenAllInnerAPKs_CapsAtMaxInnerAPKs(t *testing.T) {
	t.Parallel()

	innerBytes := makeInnerAPKWithDEX(t)

	var outerBuf bytes.Buffer
	outerW := zip.NewWriter(&outerBuf)
	count := maxInnerAPKs + 10
	for i := range count {
		name := "split_" + string(rune('A'+i/26)) + string(rune('a'+i%26)) + ".apk"
		w, err := outerW.Create(name)
		require.NoError(t, err)
		_, err = w.Write(innerBytes)
		require.NoError(t, err)
	}
	require.NoError(t, outerW.Close())

	outerReader := bytes.NewReader(outerBuf.Bytes())
	zr, err := zip.NewReader(outerReader, int64(outerBuf.Len()))
	require.NoError(t, err)

	readers, diags := OpenAllInnerAPKs(zr, 10<<20)

	assert.LessOrEqual(t, len(readers), maxInnerAPKs)

	var found bool
	for _, d := range diags {
		if d.Code == "dex.too_many_inner_apks" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected diagnostic about too many inner APKs")
}

func TestFindNestedAPK_SkipsValidationFailureAndTriesNext(t *testing.T) {
	t.Parallel()

	makeEmpty := func() []byte {
		var buf bytes.Buffer
		w := zip.NewWriter(&buf)
		require.NoError(t, w.Close())
		return buf.Bytes()
	}

	var outerBuf bytes.Buffer
	outerW := zip.NewWriter(&outerBuf)
	for _, name := range []string{"bad.apk", "good.apk"} {
		w, err := outerW.Create(name)
		require.NoError(t, err)
		_, err = w.Write(makeEmpty())
		require.NoError(t, err)
	}
	require.NoError(t, outerW.Close())

	outerReader := bytes.NewReader(outerBuf.Bytes())
	zr, err := zip.NewReader(outerReader, int64(outerBuf.Len()))
	require.NoError(t, err)

	calls := 0
	rejectFirst := InnerArchiveValidator(func(_ *zip.Reader) error {
		calls++
		if calls == 1 {
			return fmt.Errorf("rejected first candidate")
		}
		return nil
	})

	inner, err := findNestedAPK(zr, []string{"bad.apk", "good.apk"}, 10<<20, rejectFirst)
	require.NoError(t, err)
	assert.NotNil(t, inner)
	assert.Equal(t, 2, calls, "validator should have been called for both candidates")
}

func TestIsConfigSplit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		expect bool
	}{
		{"config.arm64_v8a.apk", true},
		{"config.en.apk", true},
		{"config.xxhdpi.apk", true},
		{"splits/config.de.apk", true},

		// Not config splits.
		{"base.apk", false},
		{"split_config.apk", false},
		{"feature_dynamic.apk", false},
		{"splits/base-master.apk", false},
		{"com.example.packet.apk", false},
		{"obbassets.apk", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expect, isConfigSplit(tt.name))
		})
	}
}

func TestContainsDEX(t *testing.T) {
	t.Parallel()

	t.Run("with DEX", func(t *testing.T) {
		t.Parallel()
		data := makeInnerAPKWithDEX(t)
		r := bytes.NewReader(data)
		zr, err := zip.NewReader(r, int64(len(data)))
		require.NoError(t, err)
		assert.True(t, containsDEX(zr))
	})

	t.Run("without DEX", func(t *testing.T) {
		t.Parallel()
		data := makeInnerAPKNoDEX(t)
		r := bytes.NewReader(data)
		zr, err := zip.NewReader(r, int64(len(data)))
		require.NoError(t, err)
		assert.False(t, containsDEX(zr))
	})
}

func TestOpenAllInnerAPKs_SkipsNoDEXSplits(t *testing.T) {
	t.Parallel()

	dexAPK := makeInnerAPKWithDEX(t)
	noDexAPK := makeInnerAPKNoDEX(t)

	var outerBuf bytes.Buffer
	outerW := zip.NewWriter(&outerBuf)

	// base.apk has DEX, feature.apk has DEX.
	for _, name := range []string{"base.apk", "feature.apk"} {
		w, err := outerW.Create(name)
		require.NoError(t, err)
		_, err = w.Write(dexAPK)
		require.NoError(t, err)
	}
	// obbassets.apk and asset_pack.apk have no DEX.
	for _, name := range []string{"obbassets.apk", "asset_pack.apk"} {
		w, err := outerW.Create(name)
		require.NoError(t, err)
		_, err = w.Write(noDexAPK)
		require.NoError(t, err)
	}
	// config split is filtered by name.
	w, err := outerW.Create("config.arm64_v8a.apk")
	require.NoError(t, err)
	_, err = w.Write(dexAPK) // even if it had DEX, config splits are skipped
	require.NoError(t, err)

	require.NoError(t, outerW.Close())

	outerReader := bytes.NewReader(outerBuf.Bytes())
	zr, err := zip.NewReader(outerReader, int64(outerBuf.Len()))
	require.NoError(t, err)

	readers, diags := OpenAllInnerAPKs(zr, 10<<20)

	var names []string
	for _, r := range readers {
		names = append(names, r.Name)
	}
	assert.ElementsMatch(t, []string{"base.apk", "feature.apk"}, names)
	assert.Empty(t, diags, "non-DEX splits should be silently filtered")
}

func TestOpenAllInnerAPKs_NonDEXSplitsDoNotCountAgainstLimit(t *testing.T) {
	t.Parallel()

	dexAPK := makeInnerAPKWithDEX(t)
	noDexAPK := makeInnerAPKNoDEX(t)

	var outerBuf bytes.Buffer
	outerW := zip.NewWriter(&outerBuf)

	// Add many non-DEX splits — these should NOT count against the limit.
	for i := range maxInnerAPKs + 50 {
		name := fmt.Sprintf("resource_%d.apk", i)
		w, err := outerW.Create(name)
		require.NoError(t, err)
		_, err = w.Write(noDexAPK)
		require.NoError(t, err)
	}
	// Add one DEX-bearing split after all the non-DEX ones.
	w, err := outerW.Create("base.apk")
	require.NoError(t, err)
	_, err = w.Write(dexAPK)
	require.NoError(t, err)

	require.NoError(t, outerW.Close())

	outerReader := bytes.NewReader(outerBuf.Bytes())
	zr, err := zip.NewReader(outerReader, int64(outerBuf.Len()))
	require.NoError(t, err)

	readers, diags := OpenAllInnerAPKs(zr, 10<<20)

	// The DEX-bearing split should be found despite many non-DEX splits.
	require.Len(t, readers, 1)
	assert.Equal(t, "base.apk", readers[0].Name)

	// No "too many" diagnostic since only 1 DEX split was counted.
	for _, d := range diags {
		assert.NotEqual(t, "dex.too_many_inner_apks", d.Code,
			"non-DEX splits should not trigger the limit")
	}
}

func TestOpenAllInnerAPKs_PacketNameNotFiltered(t *testing.T) {
	t.Parallel()

	// Regression: "com.example.packet.apk" should NOT be excluded.
	// The old substring-based filter would have matched "pack" in "packet".
	dexAPK := makeInnerAPKWithDEX(t)

	var outerBuf bytes.Buffer
	outerW := zip.NewWriter(&outerBuf)
	w, err := outerW.Create("com.example.packet.apk")
	require.NoError(t, err)
	_, err = w.Write(dexAPK)
	require.NoError(t, err)
	require.NoError(t, outerW.Close())

	outerReader := bytes.NewReader(outerBuf.Bytes())
	zr, err := zip.NewReader(outerReader, int64(outerBuf.Len()))
	require.NoError(t, err)

	readers, diags := OpenAllInnerAPKs(zr, 10<<20)

	require.Len(t, readers, 1)
	assert.Equal(t, "com.example.packet.apk", readers[0].Name)
	assert.Empty(t, diags)
}

func TestOpenAllInnerAPKs_OversizeIsInfo_CorruptIsWarn(t *testing.T) {
	t.Parallel()

	dexAPK := makeInnerAPKWithDEX(t)

	var outerBuf bytes.Buffer
	outerW := zip.NewWriter(&outerBuf)

	// A normal DEX-bearing APK (will succeed).
	w, err := outerW.Create("base.apk")
	require.NoError(t, err)
	_, err = w.Write(dexAPK)
	require.NoError(t, err)

	// A large APK that will exceed the size limit → info diagnostic.
	w, err = outerW.Create("huge.apk")
	require.NoError(t, err)
	bigData := make([]byte, 2048)
	_, err = w.Write(bigData) // will exceed our limit
	require.NoError(t, err)

	// Corrupt data that is not a valid ZIP → warn diagnostic.
	w, err = outerW.Create("corrupt.apk")
	require.NoError(t, err)
	_, err = w.Write([]byte("this is not a zip"))
	require.NoError(t, err)

	require.NoError(t, outerW.Close())

	outerReader := bytes.NewReader(outerBuf.Bytes())
	zr, err := zip.NewReader(outerReader, int64(outerBuf.Len()))
	require.NoError(t, err)

	// Use a small maxEntryBytes so base.apk fits but huge.apk triggers
	// ErrEntryOversize.
	readers, diags := OpenAllInnerAPKs(zr, 1024)

	// base.apk should succeed (it's small enough).
	var names []string
	for _, r := range readers {
		names = append(names, r.Name)
	}
	assert.Contains(t, names, "base.apk")

	// Check diagnostics: huge.apk → info, corrupt.apk → warn.
	diagMap := make(map[string]string)
	for _, d := range diags {
		// Extract the APK name from the message for keying.
		for _, apk := range []string{"huge.apk", "corrupt.apk"} {
			if strings.Contains(d.Message, apk) {
				diagMap[apk] = d.Severity
			}
		}
	}
	assert.Equal(t, "info", diagMap["huge.apk"], "oversize split should produce info diagnostic")
	assert.Equal(t, "warn", diagMap["corrupt.apk"], "corrupt split should produce warn diagnostic")
}
