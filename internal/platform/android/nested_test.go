package android

import (
	"archive/zip"
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenAllInnerAPKs_CapsAtMaxInnerAPKs(t *testing.T) {
	t.Parallel()

	// Build an outer ZIP containing maxInnerAPKs+10 inner .apk entries.
	// Each inner APK is a minimal valid ZIP (empty archive).
	var outerBuf bytes.Buffer
	outerW := zip.NewWriter(&outerBuf)

	// Create a minimal valid empty ZIP to use as each inner APK.
	var innerBuf bytes.Buffer
	innerW := zip.NewWriter(&innerBuf)
	require.NoError(t, innerW.Close())
	innerBytes := innerBuf.Bytes()

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

	// Should have a diagnostic about exceeding the limit.
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

	// Create two valid inner APKs.
	makeInnerAPK := func() []byte {
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
		_, err = w.Write(makeInnerAPK())
		require.NoError(t, err)
	}
	require.NoError(t, outerW.Close())

	outerReader := bytes.NewReader(outerBuf.Bytes())
	zr, err := zip.NewReader(outerReader, int64(outerBuf.Len()))
	require.NoError(t, err)

	// Validator that rejects "bad.apk" (first candidate) but would
	// accept "good.apk" (second candidate). We track which archives
	// were validated by counting calls.
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

func TestIsLikelyDEXSplit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		expect bool
	}{
		// Should be kept (likely contain DEX).
		{"base.apk", true},
		{"split_config.apk", true},       // not "config." prefix after stripping dir
		{"feature_dynamic.apk", true},
		{"splits/base-master.apk", true},

		// Should be filtered out.
		{"obbassets.apk", false},
		{"config.arm64_v8a.apk", false},
		{"config.en.apk", false},
		{"config.xxhdpi.apk", false},
		{"asset_pack_main.apk", false},
		{"obb_main.apk", false},
		{"splits/config.de.apk", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expect, isLikelyDEXSplit(tt.name))
		})
	}
}

func TestOpenAllInnerAPKs_SkipsAssetAndOBBSplits(t *testing.T) {
	t.Parallel()

	var innerBuf bytes.Buffer
	innerW := zip.NewWriter(&innerBuf)
	require.NoError(t, innerW.Close())
	innerBytes := innerBuf.Bytes()

	var outerBuf bytes.Buffer
	outerW := zip.NewWriter(&outerBuf)
	for _, name := range []string{"base.apk", "obbassets.apk", "config.arm64_v8a.apk", "feature.apk"} {
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

	var names []string
	for _, r := range readers {
		names = append(names, r.Name)
	}
	assert.ElementsMatch(t, []string{"base.apk", "feature.apk"}, names)
	assert.Empty(t, diags, "filtered splits should not produce diagnostics")
}
