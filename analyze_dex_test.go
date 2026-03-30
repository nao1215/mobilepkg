package mobilepkg

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnalyzeDex_NoDexFiles(t *testing.T) {
	t.Parallel()

	// Create a ZIP with no DEX files.
	buf := createZipWithFiles(t, map[string][]byte{
		"AndroidManifest.xml": []byte("<manifest/>"),
	})
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	require.NoError(t, err)

	findings, diags := analyzeDex([]namedReader{{reader: zr}}, FormatAPK, 512<<20)
	assert.Empty(t, findings)
	assert.Empty(t, diags)
}

func TestAnalyzeDex_WithSecrets(t *testing.T) {
	t.Parallel()

	dexData := buildMinimalTestDEX(t, []string{
		"AKIAIOSFODNN7EXAMPLE",
		"normal string",
		"http://api.example.com/v1",
	})

	buf := createZipWithFiles(t, map[string][]byte{
		"classes.dex": dexData,
	})
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	require.NoError(t, err)

	findings, diags := analyzeDex([]namedReader{{reader: zr}}, FormatAPK, 512<<20)
	assert.Empty(t, diags)
	require.NotEmpty(t, findings)

	// Should have at least a secret finding and a cleartext finding.
	categories := make([]string, 0, len(findings))
	for _, f := range findings {
		categories = append(categories, f.Category)
	}
	assert.Contains(t, categories, "dex_secret")
	assert.Contains(t, categories, "dex_cleartext")
}

func TestAnalyzeDex_InvalidDEX(t *testing.T) {
	t.Parallel()

	buf := createZipWithFiles(t, map[string][]byte{
		"classes.dex": []byte("not a dex file"),
	})
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	require.NoError(t, err)

	findings, diags := analyzeDex([]namedReader{{reader: zr}}, FormatAPK, 512<<20)
	assert.Empty(t, findings)
	require.Len(t, diags, 1)
	assert.Equal(t, "dex.parse_failed", diags[0].Code)
}

func TestAnalyzeDex_MultipleDexFiles(t *testing.T) {
	t.Parallel()

	dex1 := buildMinimalTestDEX(t, []string{"AKIAIOSFODNN7EXAMPLE"})
	dex2 := buildMinimalTestDEX(t, []string{"http://insecure.example.org/api"})

	buf := createZipWithFiles(t, map[string][]byte{
		"classes.dex":  dex1,
		"classes2.dex": dex2,
	})
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	require.NoError(t, err)

	findings, diags := analyzeDex([]namedReader{{reader: zr}}, FormatAPK, 512<<20)
	assert.Empty(t, diags)

	categories := make([]string, 0, len(findings))
	for _, f := range findings {
		categories = append(categories, f.Category)
	}
	assert.Contains(t, categories, "dex_secret")
	assert.Contains(t, categories, "dex_cleartext")
}

func TestAnalyzeDex_NestedPathIgnored(t *testing.T) {
	t.Parallel()

	dexData := buildMinimalTestDEX(t, []string{"AKIAIOSFODNN7EXAMPLE"})

	// DEX inside a subdirectory should be ignored.
	buf := createZipWithFiles(t, map[string][]byte{
		"lib/classes.dex": dexData,
	})
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	require.NoError(t, err)

	findings, diags := analyzeDex([]namedReader{{reader: zr}}, FormatAPK, 512<<20)
	assert.Empty(t, findings)
	assert.Empty(t, diags)
}

func TestIsDexEntry(t *testing.T) {
	t.Parallel()

	t.Run("APK format", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name string
			want bool
		}{
			{"classes.dex", true},
			{"classes2.dex", true},
			{"classes10.dex", true},
			{"lib/classes.dex", false},
			{"AndroidManifest.xml", false},
			{"classes.jar", false},
			{"resources.arsc", false},
			{"base/dex/classes.dex", false},
		}
		for _, tt := range tests {
			assert.Equal(t, tt.want, isDexEntry(tt.name, FormatAPK), tt.name)
		}
	})

	t.Run("AAB format", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name string
			want bool
		}{
			{"base/dex/classes.dex", true},
			{"base/dex/classes2.dex", true},
			{"feature/dex/classes.dex", true},
			{"feature/dex/classes2.dex", true},
			{"classes.dex", false},
			{"base/manifest/AndroidManifest.xml", false},
			{"base/dex/sub/classes.dex", false},
		}
		for _, tt := range tests {
			assert.Equal(t, tt.want, isDexEntry(tt.name, FormatAAB), tt.name)
		}
	})
}

// createZipWithFiles creates an in-memory ZIP archive with the given files.
func createZipWithFiles(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write(data)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// buildMinimalTestDEX builds a minimal DEX file with the given strings.
func buildMinimalTestDEX(t *testing.T, strings []string) []byte {
	t.Helper()

	le := binary.LittleEndian
	const hdrSize = 0x70
	const endian = 0x12345678

	hdr := make([]byte, hdrSize)

	stringIDsOff := hdrSize
	stringIDsSize := len(strings)
	stringIDsBytes := make([]byte, stringIDsSize*4)

	dataOff := stringIDsOff + len(stringIDsBytes)
	var dataBytes []byte
	for i, s := range strings {
		off := dataOff + len(dataBytes)
		le.PutUint32(stringIDsBytes[i*4:], uint32(off))
		dataBytes = testAppendULEB128(dataBytes, uint32(len(s)))
		dataBytes = append(dataBytes, []byte(s)...)
		dataBytes = append(dataBytes, 0)
	}

	fileSize := dataOff + len(dataBytes)

	copy(hdr[0:8], "dex\n035\x00")
	le.PutUint32(hdr[32:36], uint32(fileSize))
	le.PutUint32(hdr[36:40], hdrSize)
	le.PutUint32(hdr[40:44], endian)
	le.PutUint32(hdr[56:60], uint32(stringIDsSize))
	le.PutUint32(hdr[60:64], uint32(stringIDsOff))
	le.PutUint32(hdr[104:108], uint32(len(dataBytes)))
	le.PutUint32(hdr[108:112], uint32(dataOff))

	out := make([]byte, 0, len(hdr)+len(stringIDsBytes)+len(dataBytes))
	out = append(out, hdr...)
	out = append(out, stringIDsBytes...)
	out = append(out, dataBytes...)
	return out
}

func testAppendULEB128(buf []byte, v uint32) []byte {
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
