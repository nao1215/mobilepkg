package dex

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTestDEX builds a minimal valid DEX file with the given strings and
// method definitions. It returns raw bytes suitable for Parse().
func buildTestDEX(t *testing.T, strings []string, methods []testMethodDef) []byte {
	t.Helper()
	b := &dexBuilder{}
	b.addStrings(strings)
	for _, m := range methods {
		b.addMethod(m)
	}
	return b.build()
}

type testMethodDef struct {
	className  string
	methodName string
	protoDesc  string
}

// dexBuilder constructs minimal DEX binaries for testing.
type dexBuilder struct {
	strings []string
	methods []testMethodDef
}

func (b *dexBuilder) addStrings(ss []string) {
	b.strings = append(b.strings, ss...)
}

func (b *dexBuilder) addMethod(m testMethodDef) {
	// Ensure referenced strings exist.
	b.ensureString(m.className)
	b.ensureString(m.methodName)
	b.ensureString(m.protoDesc)
	b.methods = append(b.methods, m)
}

func (b *dexBuilder) ensureString(s string) {
	for _, existing := range b.strings {
		if existing == s {
			return
		}
	}
	b.strings = append(b.strings, s)
}

func (b *dexBuilder) stringIndex(s string) uint32 {
	for i, existing := range b.strings {
		if existing == s {
			return uint32(i)
		}
	}
	return 0
}

func (b *dexBuilder) build() []byte {
	le := binary.LittleEndian
	// We'll build the DEX in sections, computing offsets as we go.

	// 1. Header (0x70 bytes)
	headerBytes := make([]byte, headerSize)

	// 2. String IDs (4 bytes each)
	stringIDsOff := headerSize
	stringIDsSize := len(b.strings)
	stringIDsBytes := make([]byte, stringIDsSize*4)

	// 3. Type IDs - one per unique class descriptor in methods
	typeMap := make(map[string]int) // descriptor -> type index
	var typeDescs []string
	for _, m := range b.methods {
		if _, ok := typeMap[m.className]; !ok {
			typeMap[m.className] = len(typeDescs)
			typeDescs = append(typeDescs, m.className)
		}
	}
	typeIDsOff := stringIDsOff + len(stringIDsBytes)
	typeIDsSize := len(typeDescs)
	typeIDsBytes := make([]byte, typeIDsSize*4)
	for i, desc := range typeDescs {
		le.PutUint32(typeIDsBytes[i*4:], b.stringIndex(desc))
	}

	// 4. Proto IDs (12 bytes each) - one per unique proto desc
	protoMap := make(map[string]int) // shorty -> proto index
	var protoDescs []string
	for _, m := range b.methods {
		if _, ok := protoMap[m.protoDesc]; !ok {
			protoMap[m.protoDesc] = len(protoDescs)
			protoDescs = append(protoDescs, m.protoDesc)
		}
	}
	protoIDsOff := typeIDsOff + len(typeIDsBytes)
	protoIDsSize := len(protoDescs)
	protoIDsBytes := make([]byte, protoIDsSize*12)
	for i, desc := range protoDescs {
		base := i * 12
		le.PutUint32(protoIDsBytes[base:], b.stringIndex(desc))
		// return_type_idx and parameters_off = 0 (simplified)
	}

	// 5. Field IDs (empty)
	fieldIDsOff := protoIDsOff + len(protoIDsBytes)

	// 6. Method IDs (8 bytes each)
	methodIDsOff := fieldIDsOff
	methodIDsSize := len(b.methods)
	methodIDsBytes := make([]byte, methodIDsSize*8)
	for i, m := range b.methods {
		base := i * 8
		le.PutUint16(methodIDsBytes[base:], uint16(typeMap[m.className]))
		le.PutUint16(methodIDsBytes[base+2:], uint16(protoMap[m.protoDesc]))
		le.PutUint32(methodIDsBytes[base+4:], b.stringIndex(m.methodName))
	}

	// 7. Class defs (empty for basic tests)
	classDefsOff := methodIDsOff + len(methodIDsBytes)

	// 8. String data section
	dataOff := classDefsOff
	// Build string data and fill string IDs with offsets.
	var stringDataBytes []byte
	for i, s := range b.strings {
		off := dataOff + len(stringDataBytes)
		le.PutUint32(stringIDsBytes[i*4:], uint32(off))
		// ULEB128 length + string bytes + null terminator
		stringDataBytes = appendULEB128(stringDataBytes, uint32(len(s)))
		stringDataBytes = append(stringDataBytes, []byte(s)...)
		stringDataBytes = append(stringDataBytes, 0) // null terminator
	}

	// Total file size.
	fileSize := dataOff + len(stringDataBytes)

	// Fill header.
	copy(headerBytes[0:8], "dex\n035\x00")
	le.PutUint32(headerBytes[32:36], uint32(fileSize))
	le.PutUint32(headerBytes[36:40], headerSize)
	le.PutUint32(headerBytes[40:44], endianConstant)
	// string_ids
	le.PutUint32(headerBytes[56:60], uint32(stringIDsSize))
	le.PutUint32(headerBytes[60:64], uint32(stringIDsOff))
	// type_ids
	le.PutUint32(headerBytes[64:68], uint32(typeIDsSize))
	le.PutUint32(headerBytes[68:72], uint32(typeIDsOff))
	// proto_ids
	le.PutUint32(headerBytes[72:76], uint32(protoIDsSize))
	le.PutUint32(headerBytes[76:80], uint32(protoIDsOff))
	// field_ids
	le.PutUint32(headerBytes[80:84], 0)
	le.PutUint32(headerBytes[84:88], uint32(fieldIDsOff))
	// method_ids
	le.PutUint32(headerBytes[88:92], uint32(methodIDsSize))
	le.PutUint32(headerBytes[92:96], uint32(methodIDsOff))
	// class_defs
	le.PutUint32(headerBytes[96:100], 0)
	le.PutUint32(headerBytes[100:104], uint32(classDefsOff))
	// data
	le.PutUint32(headerBytes[104:108], uint32(len(stringDataBytes)))
	le.PutUint32(headerBytes[108:112], uint32(dataOff))

	// Assemble.
	out := make([]byte, 0, len(headerBytes)+len(stringIDsBytes)+len(typeIDsBytes)+len(protoIDsBytes)+len(methodIDsBytes)+len(stringDataBytes))
	out = append(out, headerBytes...)
	out = append(out, stringIDsBytes...)
	out = append(out, typeIDsBytes...)
	out = append(out, protoIDsBytes...)
	out = append(out, methodIDsBytes...)
	out = append(out, stringDataBytes...)

	return out
}

func appendULEB128(buf []byte, v uint32) []byte {
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

func TestParse_ValidMinimal(t *testing.T) {
	t.Parallel()

	data := buildTestDEX(t, []string{"hello", "world", "Ljava/lang/Object;"}, nil)

	f, err := Parse(data)
	require.NoError(t, err)

	strs := f.Strings()
	assert.Contains(t, strs, "hello")
	assert.Contains(t, strs, "world")
	assert.Contains(t, strs, "Ljava/lang/Object;")
}

func TestParse_BadMagic(t *testing.T) {
	t.Parallel()

	data := make([]byte, headerSize)
	copy(data[0:8], "notadex!")
	binary.LittleEndian.PutUint32(data[40:44], endianConstant)

	_, err := Parse(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid magic")
}

func TestParse_Truncated(t *testing.T) {
	t.Parallel()

	_, err := Parse(make([]byte, 10))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "file too small")
}

func TestParse_BadEndianTag(t *testing.T) {
	t.Parallel()

	data := make([]byte, headerSize)
	copy(data[0:4], dexMagicPrefix)
	binary.LittleEndian.PutUint32(data[40:44], 0xDEADBEEF)

	_, err := Parse(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported endian tag")
}

func TestParse_EmptyDEX(t *testing.T) {
	t.Parallel()

	data := buildTestDEX(t, nil, nil)
	f, err := Parse(data)
	require.NoError(t, err)
	assert.Empty(t, f.Strings())
	assert.Empty(t, f.Methods())
	assert.Empty(t, f.Classes())
}

func TestMethods(t *testing.T) {
	t.Parallel()

	methods := []testMethodDef{
		{className: "Lcom/example/Foo;", methodName: "bar", protoDesc: "V"},
		{className: "Ljava/lang/Runtime;", methodName: "exec", protoDesc: "VL"},
	}
	data := buildTestDEX(t, nil, methods)

	f, err := Parse(data)
	require.NoError(t, err)

	refs := f.Methods()
	require.Len(t, refs, 2)
	assert.Equal(t, "Lcom/example/Foo;", refs[0].ClassName)
	assert.Equal(t, "bar", refs[0].MethodName)
	assert.Equal(t, "Ljava/lang/Runtime;", refs[1].ClassName)
	assert.Equal(t, "exec", refs[1].MethodName)
}

func TestDecodeMUTF8_ASCII(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "hello", decodeMUTF8([]byte("hello")))
}

func TestDecodeMUTF8_EncodedNull(t *testing.T) {
	t.Parallel()
	// Null is encoded as 0xC0 0x80 in MUTF-8.
	input := []byte{0x41, 0xC0, 0x80, 0x42} // "A\0B"
	result := decodeMUTF8(input)
	assert.Equal(t, "A\x00B", result)
}

func TestDecodeMUTF8_TwoByte(t *testing.T) {
	t.Parallel()
	// U+00A9 (copyright) = 0xC2 0xA9 in UTF-8/MUTF-8
	input := []byte{0xC2, 0xA9}
	result := decodeMUTF8(input)
	assert.Equal(t, "\u00A9", result)
}

func TestReadULEB128(t *testing.T) {
	t.Parallel()

	t.Run("single byte", func(t *testing.T) {
		t.Parallel()
		val, n, err := readULEB128([]byte{0x05}, 0)
		require.NoError(t, err)
		assert.Equal(t, uint32(5), val)
		assert.Equal(t, 1, n)
	})

	t.Run("two bytes", func(t *testing.T) {
		t.Parallel()
		val, n, err := readULEB128([]byte{0x80, 0x01}, 0) // 128
		require.NoError(t, err)
		assert.Equal(t, uint32(128), val)
		assert.Equal(t, 2, n)
	})

	t.Run("out of bounds", func(t *testing.T) {
		t.Parallel()
		_, _, err := readULEB128([]byte{}, 0)
		assert.Error(t, err)
	})
}

func TestDescriptorToInternal(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "android/webkit/WebSettings", descriptorToInternal("Landroid/webkit/WebSettings;"))
	assert.Equal(t, "java/lang/Runtime", descriptorToInternal("Ljava/lang/Runtime;"))
	assert.Equal(t, "int", descriptorToInternal("int"))
}

func TestParse_StringIDsExceedsFileSize(t *testing.T) {
	t.Parallel()

	data := make([]byte, headerSize)
	copy(data[0:4], dexMagicPrefix)
	le := binary.LittleEndian
	le.PutUint32(data[40:44], endianConstant)
	// Claim 1000 strings but file is only headerSize bytes.
	le.PutUint32(data[56:60], 1000)
	le.PutUint32(data[60:64], headerSize)

	_, err := Parse(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds file size")
}
