package dex

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildDEXWithCode builds a DEX file that contains:
//   - A class "LTestClass;" with a method "testMethod" whose code contains
//     invoke-virtual instructions calling each of the target methods.
//   - Target methods in the method table.
func buildDEXWithCode(t *testing.T, callerClass string, callerMethod string, targets []testMethodDef) []byte {
	t.Helper()
	le := binary.LittleEndian

	// Collect all strings.
	strSet := make(map[string]struct{})
	strSet[callerClass] = struct{}{}
	strSet[callerMethod] = struct{}{}
	strSet["V"] = struct{}{} // proto shorty
	for _, tgt := range targets {
		strSet[tgt.className] = struct{}{}
		strSet[tgt.methodName] = struct{}{}
		if tgt.protoDesc != "" {
			strSet[tgt.protoDesc] = struct{}{}
		}
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
		addStr(tgt.className)
		addStr(tgt.methodName)
		if tgt.protoDesc == "" {
			addStr("V")
		} else {
			addStr(tgt.protoDesc)
		}
	}

	// Types: callerClass + each unique target class.
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
		addType(tgt.className)
	}

	// Protos: one for "V" (or whatever shorty).
	type proto struct {
		shortyIdx uint32
	}
	protoIdx := make(map[string]uint16)
	var protos []proto
	addProto := func(shorty string) {
		if _, ok := protoIdx[shorty]; !ok {
			protoIdx[shorty] = uint16(len(protos))
			protos = append(protos, proto{shortyIdx: strIdx[shorty]})
		}
	}
	addProto("V")
	for _, tgt := range targets {
		desc := tgt.protoDesc
		if desc == "" {
			desc = "V"
		}
		addProto(desc)
	}

	// Methods: caller method (index 0) + target methods.
	type methodEntry struct {
		classIdx uint16
		protoIdx uint16
		nameIdx  uint32
	}
	methods := make([]methodEntry, 0, 1+len(targets))
	callerMethodIdx := len(methods)
	methods = append(methods, methodEntry{
		classIdx: typeIdx[callerClass],
		protoIdx: protoIdx["V"],
		nameIdx:  strIdx[callerMethod],
	})

	targetMethodIndices := make([]uint16, len(targets))
	for i, tgt := range targets {
		desc := tgt.protoDesc
		if desc == "" {
			desc = "V"
		}
		targetMethodIndices[i] = uint16(len(methods))
		methods = append(methods, methodEntry{
			classIdx: typeIdx[tgt.className],
			protoIdx: protoIdx[desc],
			nameIdx:  strIdx[tgt.methodName],
		})
	}

	// Now build the binary sections.

	// 1. Header placeholder.
	hdr := make([]byte, headerSize)

	// 2. String IDs.
	stringIDsOff := headerSize
	stringIDsBytes := make([]byte, len(strs)*4)

	// 3. Type IDs.
	typeIDsOff := stringIDsOff + len(stringIDsBytes)
	typeIDsBytes := make([]byte, len(typeStrIDs)*4)
	for i, sid := range typeStrIDs {
		le.PutUint32(typeIDsBytes[i*4:], sid)
	}

	// 4. Proto IDs (12 bytes each).
	protoIDsOff := typeIDsOff + len(typeIDsBytes)
	protoIDsBytes := make([]byte, len(protos)*12)
	for i, p := range protos {
		le.PutUint32(protoIDsBytes[i*12:], p.shortyIdx)
	}

	// 5. Field IDs (empty).
	fieldIDsOff := protoIDsOff + len(protoIDsBytes)

	// 6. Method IDs (8 bytes each).
	methodIDsOff := fieldIDsOff
	methodIDsBytes := make([]byte, len(methods)*8)
	for i, m := range methods {
		base := i * 8
		le.PutUint16(methodIDsBytes[base:], m.classIdx)
		le.PutUint16(methodIDsBytes[base+2:], m.protoIdx)
		le.PutUint32(methodIDsBytes[base+4:], m.nameIdx)
	}

	// 7. Class defs (32 bytes each). We have 1 class.
	classDefsOff := methodIDsOff + len(methodIDsBytes)
	classDefsBytes := make([]byte, 32)
	le.PutUint32(classDefsBytes[0:], uint32(typeIdx[callerClass])) // class_idx

	// class_data_off will be filled later.

	// 8. Data section: string data + class_data + code_item.
	dataOff := classDefsOff + len(classDefsBytes)

	// 8a. String data.
	var stringDataBytes []byte
	for i, s := range strs {
		off := dataOff + len(stringDataBytes)
		le.PutUint32(stringIDsBytes[i*4:], uint32(off))
		stringDataBytes = appendULEB128(stringDataBytes, uint32(len(s)))
		stringDataBytes = append(stringDataBytes, []byte(s)...)
		stringDataBytes = append(stringDataBytes, 0)
	}

	// 8b. Code item.
	// Build instructions: for each target, emit invoke-virtual (0x6E).
	// Format 35c: [opcode|arg_count, method_idx, reg_pair1, reg_pair2]
	//   byte 0: opcode (0x6E)
	//   byte 1: arg count << 4 | reg
	//   bytes 2-3: method_idx (uint16 LE)
	//   bytes 4-5: 0 (register pair)
	var insnsBytes []byte
	for _, midx := range targetMethodIndices {
		// invoke-virtual {v0}, method@midx
		insn := make([]byte, 6)
		insn[0] = opInvokeVirtual // 0x6E
		insn[1] = 0x10            // 1 arg, register v0
		le.PutUint16(insn[2:4], midx)
		insnsBytes = append(insnsBytes, insn...)
	}
	// Add return-void (0x0E) as the last instruction.
	insnsBytes = append(insnsBytes, 0x0E, 0x00)

	// Pad to even length.
	if len(insnsBytes)%2 != 0 {
		insnsBytes = append(insnsBytes, 0x00)
	}

	insnsSize := len(insnsBytes) / 2 // in 16-bit code units

	codeItemOff := dataOff + len(stringDataBytes)
	// code_item: registers_size(2) + ins_size(2) + outs_size(2) + tries_size(2) +
	//            debug_info_off(4) + insns_size(4) + insns[insns_size]
	codeItemBytes := make([]byte, 16+len(insnsBytes))
	le.PutUint16(codeItemBytes[0:], 2)                  // registers_size
	le.PutUint16(codeItemBytes[2:], 0)                  // ins_size
	le.PutUint16(codeItemBytes[4:], 1)                  // outs_size
	le.PutUint16(codeItemBytes[6:], 0)                  // tries_size
	le.PutUint32(codeItemBytes[8:], 0)                  // debug_info_off
	le.PutUint32(codeItemBytes[12:], uint32(insnsSize)) // insns_size
	copy(codeItemBytes[16:], insnsBytes)

	// 8c. Class data item.
	classDataOff := codeItemOff + len(codeItemBytes)
	var classDataBytes []byte
	classDataBytes = appendULEB128(classDataBytes, 0) // static_fields_size
	classDataBytes = appendULEB128(classDataBytes, 0) // instance_fields_size
	classDataBytes = appendULEB128(classDataBytes, 1) // direct_methods_size
	classDataBytes = appendULEB128(classDataBytes, 0) // virtual_methods_size
	// encoded_method for the caller:
	classDataBytes = appendULEB128(classDataBytes, uint32(callerMethodIdx)) // method_idx_diff
	classDataBytes = appendULEB128(classDataBytes, 0x0001)                  // access_flags (public)
	classDataBytes = appendULEB128(classDataBytes, uint32(codeItemOff))     // code_off

	// Fill class_data_off in class def.
	le.PutUint32(classDefsBytes[24:], uint32(classDataOff))

	// Total data section.
	allDataBytes := make([]byte, 0, len(stringDataBytes)+len(codeItemBytes)+len(classDataBytes))
	allDataBytes = append(allDataBytes, stringDataBytes...)
	allDataBytes = append(allDataBytes, codeItemBytes...)
	allDataBytes = append(allDataBytes, classDataBytes...)

	fileSize := dataOff + len(allDataBytes)

	// Fill header.
	copy(hdr[0:8], "dex\n035\x00")
	le.PutUint32(hdr[32:36], uint32(fileSize))
	le.PutUint32(hdr[36:40], headerSize)
	le.PutUint32(hdr[40:44], endianConstant)
	le.PutUint32(hdr[56:60], uint32(len(strs)))
	le.PutUint32(hdr[60:64], uint32(stringIDsOff))
	le.PutUint32(hdr[64:68], uint32(len(typeStrIDs)))
	le.PutUint32(hdr[68:72], uint32(typeIDsOff))
	le.PutUint32(hdr[72:76], uint32(len(protos)))
	le.PutUint32(hdr[76:80], uint32(protoIDsOff))
	le.PutUint32(hdr[80:84], 0)
	le.PutUint32(hdr[84:88], uint32(fieldIDsOff))
	le.PutUint32(hdr[88:92], uint32(len(methods)))
	le.PutUint32(hdr[92:96], uint32(methodIDsOff))
	le.PutUint32(hdr[96:100], 1) // 1 class def
	le.PutUint32(hdr[100:104], uint32(classDefsOff))
	le.PutUint32(hdr[104:108], uint32(len(allDataBytes)))
	le.PutUint32(hdr[108:112], uint32(dataOff))

	out := make([]byte, 0, fileSize)
	out = append(out, hdr...)
	out = append(out, stringIDsBytes...)
	out = append(out, typeIDsBytes...)
	out = append(out, protoIDsBytes...)
	out = append(out, methodIDsBytes...)
	out = append(out, classDefsBytes...)
	out = append(out, allDataBytes...)

	return out
}

func TestFindMethodCalls_InvokeVirtual(t *testing.T) {
	t.Parallel()

	data := buildDEXWithCode(t, "Lcom/test/Caller;", "doStuff", []testMethodDef{
		{className: "Landroid/webkit/WebSettings;", methodName: "setJavaScriptEnabled"},
		{className: "Ljava/lang/Runtime;", methodName: "exec"},
	})

	f, err := Parse(data)
	require.NoError(t, err)

	// Find setJavaScriptEnabled calls.
	calls := f.FindMethodCalls("android/webkit/WebSettings", "setJavaScriptEnabled")
	require.Len(t, calls, 1)
	assert.Equal(t, "Lcom/test/Caller;", calls[0].CallerClass)
	assert.Equal(t, "doStuff", calls[0].CallerMethod)
	assert.Equal(t, "Landroid/webkit/WebSettings;", calls[0].Target.ClassName)
	assert.Equal(t, "setJavaScriptEnabled", calls[0].Target.MethodName)

	// Find Runtime.exec calls.
	calls = f.FindMethodCalls("java/lang/Runtime", "exec")
	require.Len(t, calls, 1)
	assert.Equal(t, "exec", calls[0].Target.MethodName)

	// No calls to non-existent method.
	calls = f.FindMethodCalls("java/lang/String", "valueOf")
	assert.Empty(t, calls)
}

func TestFindMethodCalls_NoCalls(t *testing.T) {
	t.Parallel()

	// DEX with methods but no code.
	data := buildTestDEX(t, []string{"hello"}, []testMethodDef{
		{className: "Lcom/Foo;", methodName: "bar", protoDesc: "V"},
	})

	f, err := Parse(data)
	require.NoError(t, err)

	calls := f.FindMethodCalls("com/Foo", "bar")
	assert.Empty(t, calls)
}

func TestFindMethodCalls_MultipleTargets(t *testing.T) {
	t.Parallel()

	data := buildDEXWithCode(t, "Lcom/app/Main;", "init", []testMethodDef{
		{className: "Ldalvik/system/DexClassLoader;", methodName: "<init>"},
		{className: "Landroid/webkit/WebView;", methodName: "addJavascriptInterface"},
		{className: "Ljava/lang/Runtime;", methodName: "exec"},
	})

	f, err := Parse(data)
	require.NoError(t, err)

	assert.Len(t, f.FindMethodCalls("dalvik/system/DexClassLoader", "<init>"), 1)
	assert.Len(t, f.FindMethodCalls("android/webkit/WebView", "addJavascriptInterface"), 1)
	assert.Len(t, f.FindMethodCalls("java/lang/Runtime", "exec"), 1)
}

func TestIsInvokeOp(t *testing.T) {
	t.Parallel()

	assert.True(t, isInvokeOp(opInvokeVirtual))
	assert.True(t, isInvokeOp(opInvokeStatic))
	assert.True(t, isInvokeOp(opInvokeDirect))
	assert.True(t, isInvokeOp(opInvokeSuper))
	assert.True(t, isInvokeOp(opInvokeInterface))
	assert.True(t, isInvokeOp(opInvokeVirtualRange))
	assert.True(t, isInvokeOp(opInvokeStaticRange))
	assert.True(t, isInvokeOp(opInvokeDirectRange))
	assert.True(t, isInvokeOp(opInvokeSuperRange))
	assert.True(t, isInvokeOp(opInvokeInterfaceRange))
	assert.False(t, isInvokeOp(0x00)) // nop
	assert.False(t, isInvokeOp(0x0E)) // return-void
}

func TestInsnWidth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		opcode byte
		want   int
	}{
		{"nop", 0x00, 2},
		{"move", 0x01, 2},
		{"move/from16", 0x02, 4},
		{"move/16", 0x03, 6},
		{"return-void", 0x0E, 2},
		{"return", 0x0F, 2},
		{"const/4", 0x12, 2},
		{"const/16", 0x13, 4},
		{"const", 0x14, 6},
		{"const/high16", 0x15, 4},
		{"const-wide", 0x18, 10},
		{"const-string", 0x1A, 4},
		{"const-string/jumbo", 0x1B, 6},
		{"const-class", 0x1C, 4},
		{"check-cast", 0x1F, 4},
		{"array-length", 0x21, 2},
		{"filled-new-array", 0x24, 6},
		{"filled-new-array/range", 0x25, 6},
		{"throw", 0x27, 2},
		{"goto", 0x28, 2},
		{"goto/16", 0x29, 4},
		{"goto/32", 0x2A, 6},
		{"invoke-virtual", opInvokeVirtual, 6},
		{"invoke-static", opInvokeStatic, 6},
		{"invoke-direct", opInvokeDirect, 6},
		{"invoke-virtual/range", opInvokeVirtualRange, 6},
		{"iget", 0x52, 4},
		{"sget", 0x60, 4},
		{"binop/2addr", 0xB0, 2},
		{"binop/lit8", 0xD8, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			insns := []byte{tt.opcode, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			got := insnWidth(insns, 0)
			assert.Equal(t, tt.want, got, "opcode 0x%02x", tt.opcode)
		})
	}
}

func TestResolveType(t *testing.T) {
	t.Parallel()

	data := buildTestDEX(t, nil, []testMethodDef{
		{className: "Ljava/lang/Object;", methodName: "toString", protoDesc: "V"},
	})
	f, err := Parse(data)
	require.NoError(t, err)

	assert.Equal(t, "Ljava/lang/Object;", f.resolveType(0))
	assert.Equal(t, "", f.resolveType(999)) // out of bounds
}
