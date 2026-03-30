package scanner

import (
	"encoding/binary"
	"testing"

	"github.com/nao1215/mobilepkg/internal/dex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildDEXWithInvoke builds a DEX with code that calls the given target methods.
func buildDEXWithInvoke(t *testing.T, targets []struct{ class, method string }) []byte {
	t.Helper()
	le := binary.LittleEndian

	callerClass := "Lcom/test/TestCaller;"
	callerMethod := "run"

	strSet := map[string]struct{}{callerClass: {}, callerMethod: {}, "V": {}}
	for _, tgt := range targets {
		strSet[tgt.class] = struct{}{}
		strSet[tgt.method] = struct{}{}
	}

	var strs []string
	strIdx := make(map[string]uint32)
	addStr := func(s string) {
		if _, ok := strIdx[s]; !ok {
			strIdx[s] = uint32(len(strs))
			strs = append(strs, s)
		}
	}
	addStr(callerClass)
	addStr(callerMethod)
	addStr("V")
	for _, tgt := range targets {
		addStr(tgt.class)
		addStr(tgt.method)
	}

	typeIdx := make(map[string]uint16)
	var typeStrIDs []uint32
	addType := func(desc string) {
		if _, ok := typeIdx[desc]; !ok {
			typeIdx[desc] = uint16(len(typeStrIDs))
			typeStrIDs = append(typeStrIDs, strIdx[desc])
		}
	}
	addType(callerClass)
	for _, tgt := range targets {
		addType(tgt.class)
	}

	protoStrIdx := strIdx["V"]

	type methodEntry struct {
		classIdx uint16
		protoIdx uint16
		nameIdx  uint32
	}
	methods := make([]methodEntry, 0, 1+len(targets))
	callerMethodIdx := len(methods)
	methods = append(methods, methodEntry{typeIdx[callerClass], 0, strIdx[callerMethod]})

	targetMethodIndices := make([]uint16, len(targets))
	for i, tgt := range targets {
		targetMethodIndices[i] = uint16(len(methods))
		methods = append(methods, methodEntry{typeIdx[tgt.class], 0, strIdx[tgt.method]})
	}

	// Build binary.
	hdr := make([]byte, 0x70)
	stringIDsOff := 0x70
	stringIDsBytes := make([]byte, len(strs)*4)
	typeIDsOff := stringIDsOff + len(stringIDsBytes)
	typeIDsBytes := make([]byte, len(typeStrIDs)*4)
	for i, sid := range typeStrIDs {
		le.PutUint32(typeIDsBytes[i*4:], sid)
	}
	protoIDsOff := typeIDsOff + len(typeIDsBytes)
	protoIDsBytes := make([]byte, 12)
	le.PutUint32(protoIDsBytes[0:], protoStrIdx)
	fieldIDsOff := protoIDsOff + len(protoIDsBytes)
	methodIDsOff := fieldIDsOff
	methodIDsBytes := make([]byte, len(methods)*8)
	for i, m := range methods {
		base := i * 8
		le.PutUint16(methodIDsBytes[base:], m.classIdx)
		le.PutUint16(methodIDsBytes[base+2:], m.protoIdx)
		le.PutUint32(methodIDsBytes[base+4:], m.nameIdx)
	}
	classDefsOff := methodIDsOff + len(methodIDsBytes)
	classDefsBytes := make([]byte, 32)
	le.PutUint32(classDefsBytes[0:], uint32(typeIdx[callerClass]))

	dataOff := classDefsOff + len(classDefsBytes)
	var stringDataBytes []byte
	for i, s := range strs {
		off := dataOff + len(stringDataBytes)
		le.PutUint32(stringIDsBytes[i*4:], uint32(off))
		stringDataBytes = testAppendULEB128(stringDataBytes, uint32(len(s)))
		stringDataBytes = append(stringDataBytes, []byte(s)...)
		stringDataBytes = append(stringDataBytes, 0)
	}

	// Code item.
	var insnsBytes []byte
	for _, midx := range targetMethodIndices {
		insn := make([]byte, 6)
		insn[0] = 0x6E // invoke-virtual
		insn[1] = 0x10
		le.PutUint16(insn[2:4], midx)
		insnsBytes = append(insnsBytes, insn...)
	}
	insnsBytes = append(insnsBytes, 0x0E, 0x00) // return-void
	if len(insnsBytes)%2 != 0 {
		insnsBytes = append(insnsBytes, 0x00)
	}

	codeItemOff := dataOff + len(stringDataBytes)
	codeItemBytes := make([]byte, 16+len(insnsBytes))
	le.PutUint16(codeItemBytes[0:], 2)
	le.PutUint32(codeItemBytes[12:], uint32(len(insnsBytes)/2))
	copy(codeItemBytes[16:], insnsBytes)

	classDataOff := codeItemOff + len(codeItemBytes)
	var classDataBytes []byte
	classDataBytes = testAppendULEB128(classDataBytes, 0)
	classDataBytes = testAppendULEB128(classDataBytes, 0)
	classDataBytes = testAppendULEB128(classDataBytes, 1)
	classDataBytes = testAppendULEB128(classDataBytes, 0)
	classDataBytes = testAppendULEB128(classDataBytes, uint32(callerMethodIdx))
	classDataBytes = testAppendULEB128(classDataBytes, 0x0001)
	classDataBytes = testAppendULEB128(classDataBytes, uint32(codeItemOff))

	le.PutUint32(classDefsBytes[24:], uint32(classDataOff))

	allData := make([]byte, 0, len(stringDataBytes)+len(codeItemBytes)+len(classDataBytes))
	allData = append(allData, stringDataBytes...)
	allData = append(allData, codeItemBytes...)
	allData = append(allData, classDataBytes...)

	fileSize := dataOff + len(allData)
	copy(hdr[0:8], "dex\n035\x00")
	le.PutUint32(hdr[32:36], uint32(fileSize))
	le.PutUint32(hdr[36:40], 0x70)
	le.PutUint32(hdr[40:44], 0x12345678)
	le.PutUint32(hdr[56:60], uint32(len(strs)))
	le.PutUint32(hdr[60:64], uint32(stringIDsOff))
	le.PutUint32(hdr[64:68], uint32(len(typeStrIDs)))
	le.PutUint32(hdr[68:72], uint32(typeIDsOff))
	le.PutUint32(hdr[72:76], 1)
	le.PutUint32(hdr[76:80], uint32(protoIDsOff))
	le.PutUint32(hdr[80:84], 0)
	le.PutUint32(hdr[84:88], uint32(fieldIDsOff))
	le.PutUint32(hdr[88:92], uint32(len(methods)))
	le.PutUint32(hdr[92:96], uint32(methodIDsOff))
	le.PutUint32(hdr[96:100], 1)
	le.PutUint32(hdr[100:104], uint32(classDefsOff))
	le.PutUint32(hdr[104:108], uint32(len(allData)))
	le.PutUint32(hdr[108:112], uint32(dataOff))

	out := make([]byte, 0, fileSize)
	out = append(out, hdr...)
	out = append(out, stringIDsBytes...)
	out = append(out, typeIDsBytes...)
	out = append(out, protoIDsBytes...)
	out = append(out, methodIDsBytes...)
	out = append(out, classDefsBytes...)
	out = append(out, allData...)
	return out
}

func parseDEXWithInvoke(t *testing.T, targets []struct{ class, method string }) *dex.File {
	t.Helper()
	data := buildDEXWithInvoke(t, targets)
	f, err := dex.Parse(data)
	require.NoError(t, err)
	return f
}

func TestInsecureWebView_WithCode(t *testing.T) {
	t.Parallel()

	df := parseDEXWithInvoke(t, []struct{ class, method string }{
		{"Landroid/webkit/WebSettings;", "setJavaScriptEnabled"},
		{"Landroid/webkit/WebView;", "addJavascriptInterface"},
	})

	ctx := &Context{DexFiles: []*dex.File{df}}
	rule := &insecureWebViewRule{}
	findings := rule.Match(ctx)

	require.Len(t, findings, 2)

	msgs := make([]string, 0, len(findings))
	for _, f := range findings {
		msgs = append(msgs, f.Message)
		assert.Equal(t, "dex_webview", f.Category)
	}
	assert.Contains(t, msgs[0], "JavaScript enabled")
	assert.Contains(t, msgs[1], "JavaScript interface")
}

func TestDangerousAPIs_WithCode(t *testing.T) {
	t.Parallel()

	df := parseDEXWithInvoke(t, []struct{ class, method string }{
		{"Ljava/lang/Runtime;", "exec"},
		{"Ldalvik/system/DexClassLoader;", "<init>"},
	})

	ctx := &Context{DexFiles: []*dex.File{df}}
	rule := &dangerousAPIsRule{}
	findings := rule.Match(ctx)

	require.Len(t, findings, 2)

	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.ID)
		assert.Equal(t, "dex_dangerous_api", f.Category)
	}
	assert.Contains(t, ids[0], "Runtime")
	assert.Contains(t, ids[1], "DexClassLoader")
}

func TestDangerousAPIs_NoMatch(t *testing.T) {
	t.Parallel()

	df := buildTestDEXWithStrings(t, []string{"nothing dangerous"})
	ctx := &Context{DexFiles: []*dex.File{df}}
	rule := &dangerousAPIsRule{}
	findings := rule.Match(ctx)
	assert.Empty(t, findings)
}

func TestInsecureWebView_NoMatch(t *testing.T) {
	t.Parallel()

	df := buildTestDEXWithStrings(t, []string{"safe string"})
	ctx := &Context{DexFiles: []*dex.File{df}}
	rule := &insecureWebViewRule{}
	findings := rule.Match(ctx)
	assert.Empty(t, findings)
}

func TestScanWithRules_Integration(t *testing.T) {
	t.Parallel()

	// DEX with code + strings.
	codeDF := parseDEXWithInvoke(t, []struct{ class, method string }{
		{"Ljava/lang/Runtime;", "exec"},
	})
	stringDF := buildTestDEXWithStrings(t, []string{
		"AKIAIOSFODNN7EXAMPLE",
		"http://insecure.api.example.com/v2",
	})

	ctx := &Context{DexFiles: []*dex.File{codeDF, stringDF}}
	findings := Scan(ctx)

	categories := make([]string, 0, len(findings))
	for _, f := range findings {
		categories = append(categories, f.Category)
	}
	assert.Contains(t, categories, "dex_dangerous_api")
	assert.Contains(t, categories, "dex_secret")
	assert.Contains(t, categories, "dex_cleartext")
}
