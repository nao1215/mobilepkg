package scanner

import (
	"encoding/binary"
	"testing"

	"github.com/nao1215/mobilepkg/internal/dex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTestDEXWithMethodCalls creates a DEX file that has string table entries
// and simulated method call structures. For lightweight argument tracking tests,
// we need a DEX with actual bytecode; for string-only tests we use the simpler builder.
// This helper creates a minimal DEX with the given strings for string-table tests.
func buildWebViewTestDEX(t *testing.T, strings []string) *dex.File {
	t.Helper()
	data := buildMinDEX(t, strings)
	f, err := dex.Parse(data)
	require.NoError(t, err)
	return f
}

func TestInsecureWebView_DetectsTargetMethods(t *testing.T) {
	t.Parallel()

	// This test verifies the rule registers all expected target methods.
	// Since we can't easily build DEX bytecode with invoke instructions,
	// we verify the target list is complete.
	expectedMethods := []string{
		"setJavaScriptEnabled",
		"addJavascriptInterface",
		"setAllowFileAccess",
		"setAllowUniversalAccessFromFileURLs",
		"setMixedContentMode",
		"setWebContentsDebuggingEnabled",
	}

	for _, method := range expectedMethods {
		found := false
		for _, wt := range webviewTargets {
			if wt.method == method {
				found = true
				break
			}
		}
		assert.True(t, found, "webviewTargets should include %s", method)
	}
}

func TestInsecureWebView_CheckTrue_Targets(t *testing.T) {
	t.Parallel()

	// Verify that checkTrue is set for the right methods.
	checkTrueMethods := map[string]bool{
		"setJavaScriptEnabled":                true,
		"setAllowFileAccess":                  true,
		"setAllowUniversalAccessFromFileURLs": true,
		"setWebContentsDebuggingEnabled":      true,
	}

	for _, wt := range webviewTargets {
		if expected, ok := checkTrueMethods[wt.method]; ok {
			assert.Equal(t, expected, wt.checkTrue,
				"%s should have checkTrue=%v", wt.method, expected)
		}
	}
}

func TestIsBoolArgTrue_ConstFour(t *testing.T) {
	t.Parallel()

	// Build a minimal DEX where we can test the argument tracking.
	// We simulate by creating a DEX and using its raw data accessor.
	// For the const/4 check, the byte pattern at offset-2 should be:
	// [dest_reg | (val << 4)] 0x12
	// Value 1 (true): high nibble = 1, so byte = 0x10, opcode = 0x12

	le := binary.LittleEndian

	// Build minimal DEX header + strings
	headerBytes := make([]byte, 0x70)
	copy(headerBytes[0:8], "dex\n035\x00")
	fileSize := 0x70 + 100 // header + some bytecode space
	le.PutUint32(headerBytes[32:36], uint32(fileSize))
	le.PutUint32(headerBytes[36:40], 0x70)
	le.PutUint32(headerBytes[40:44], 0x12345678) // endian

	data := make([]byte, fileSize)
	copy(data, headerBytes)

	f, err := dex.Parse(data)
	require.NoError(t, err)

	// dex.Parse stores a reference to the input slice, so mutations to data
	// are visible through f.RawData(). This lets us inject synthetic bytecode
	// to test isBoolArgTrue without building a full DEX with code_items.

	// Test with a synthetic CallSite at a known offset.
	// Place const/4 v0, 1 (true) at offset 0x70, invoke at 0x72
	data[0x70] = 0x12 // const/4 opcode
	data[0x71] = 0x10 // v0, value=1 (true)
	// invoke would be at 0x72

	cs := dex.CallSite{Offset: 0x72}
	assert.True(t, isBoolArgTrue(f, cs), "should detect const/4 with value 1 as true")

	// Now test const/4 v0, 0 (false)
	data[0x71] = 0x00 // v0, value=0 (false)
	assert.False(t, isBoolArgTrue(f, cs), "should detect const/4 with value 0 as false")
}

func TestGetPrecedingConstString(t *testing.T) {
	t.Parallel()

	// Create a DEX with a string table entry at index 0.
	df := buildWebViewTestDEX(t, []string{"http://example.com/page"})
	data := df.RawData()
	if len(data) < 0x80 {
		t.Skip("DEX too small for bytecode test")
	}

	// Place const-string v0, #0 at offset (len(data) - 10)
	// const-string is opcode 0x1A, format: [AA] 1A [BBBB]
	off := len(data) - 10
	data[off] = 0x1A // const-string opcode
	data[off+1] = 0  // register vAA = v0
	data[off+2] = 0  // string index low byte
	data[off+3] = 0  // string index high byte

	cs := dex.CallSite{Offset: uint32(off + 4)}
	got := getPrecedingConstString(df, cs)
	assert.Equal(t, "http://example.com/page", got)
}

func TestInsecureWebView_EmptyContext(t *testing.T) {
	t.Parallel()

	ctx := &Context{}
	rule := &insecureWebViewRule{}
	findings := rule.Match(ctx)
	assert.Empty(t, findings)
}

func TestInsecureWebView_AllCheckTrueTargets(t *testing.T) {
	t.Parallel()

	expected := map[string]bool{
		"setJavaScriptEnabled":                true,
		"setAllowFileAccess":                  true,
		"setAllowUniversalAccessFromFileURLs": true,
		"setWebContentsDebuggingEnabled":      true,
	}

	actual := make(map[string]bool)
	for _, wt := range webviewTargets {
		if wt.checkTrue {
			actual[wt.method] = true
		}
	}

	assert.Equal(t, expected, actual, "checkTrue targets should match expected set")
}
