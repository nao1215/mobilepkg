package android

import (
	"archive/zip"
	"bytes"
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
	for i := 0; i < count; i++ {
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
