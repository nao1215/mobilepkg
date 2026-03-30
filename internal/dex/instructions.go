package dex

import (
	"encoding/binary"
	"strings"
)

// Dalvik invoke-* opcodes.
const (
	opInvokeVirtual   = 0x6E
	opInvokeSuper     = 0x6F
	opInvokeDirect    = 0x70
	opInvokeStatic    = 0x71
	opInvokeInterface = 0x72

	opInvokeVirtualRange   = 0x74
	opInvokeSuperRange     = 0x75
	opInvokeDirectRange    = 0x76
	opInvokeStaticRange    = 0x77
	opInvokeInterfaceRange = 0x78
)

// ensureCallIndex builds the inverted call index on first access.
func (f *File) ensureCallIndex() {
	if f.callIndex != nil {
		return
	}
	f.callIndex = make(map[methodKey][]CallSite)
	f.buildCallIndex()
}

// buildCallIndex scans all class_defs → class_data → code_items for
// invoke-* instructions and populates the call index.
func (f *File) buildCallIndex() {
	for _, cd := range f.classes {
		if cd.ClassDataOff == 0 {
			continue
		}
		callerClass := f.resolveType(cd.ClassIdx)
		f.scanClassData(int(cd.ClassDataOff), callerClass)
	}
}

// scanClassData parses a class_data_item and scans each method's code
// for invoke-* instructions.
func (f *File) scanClassData(off int, callerClass string) {
	data := f.data
	if off >= len(data) {
		return
	}

	pos := off

	// static_fields_size
	staticFieldsSize, n, err := readULEB128(data, pos)
	if err != nil {
		return
	}
	pos += n

	// instance_fields_size
	instanceFieldsSize, n, err := readULEB128(data, pos)
	if err != nil {
		return
	}
	pos += n

	// direct_methods_size
	directMethodsSize, n, err := readULEB128(data, pos)
	if err != nil {
		return
	}
	pos += n

	// virtual_methods_size
	virtualMethodsSize, n, err := readULEB128(data, pos)
	if err != nil {
		return
	}
	pos += n

	// Skip encoded fields (each has 2 ULEB128 values).
	pos = skipEncodedFields(data, pos, int(staticFieldsSize))
	pos = skipEncodedFields(data, pos, int(instanceFieldsSize))

	// Process direct methods.
	f.scanEncodedMethods(data, pos, int(directMethodsSize), callerClass)
	pos = skipEncodedMethods(data, pos, int(directMethodsSize))

	// Process virtual methods.
	f.scanEncodedMethods(data, pos, int(virtualMethodsSize), callerClass)
}

func skipEncodedFields(data []byte, pos, count int) int {
	for range count {
		_, n, err := readULEB128(data, pos) // field_idx_diff
		if err != nil {
			return pos
		}
		pos += n
		_, n, err = readULEB128(data, pos) // access_flags
		if err != nil {
			return pos
		}
		pos += n
	}
	return pos
}

func skipEncodedMethods(data []byte, pos, count int) int {
	for range count {
		_, n, err := readULEB128(data, pos) // method_idx_diff
		if err != nil {
			return pos
		}
		pos += n
		_, n, err = readULEB128(data, pos) // access_flags
		if err != nil {
			return pos
		}
		pos += n
		_, n, err = readULEB128(data, pos) // code_off
		if err != nil {
			return pos
		}
		pos += n
	}
	return pos
}

// scanEncodedMethods iterates encoded_method entries, resolves method names,
// and scans each code_item for invoke instructions.
func (f *File) scanEncodedMethods(data []byte, pos, count int, callerClass string) {
	var methodIdx uint32
	for range count {
		diff, n, err := readULEB128(data, pos)
		if err != nil {
			return
		}
		pos += n
		methodIdx += diff

		_, n, err = readULEB128(data, pos) // access_flags
		if err != nil {
			return
		}
		pos += n

		codeOff, n, err := readULEB128(data, pos)
		if err != nil {
			return
		}
		pos += n

		if codeOff == 0 {
			continue
		}

		callerMethod := ""
		if int(methodIdx) < len(f.methods) {
			m := f.methods[methodIdx]
			if int(m.NameIdx) < len(f.strings) {
				callerMethod = f.strings[m.NameIdx]
			}
		}

		f.scanCodeItem(int(codeOff), callerClass, callerMethod)
	}
}

// scanCodeItem reads a code_item at the given offset and scans its
// instruction array for invoke-* opcodes.
func (f *File) scanCodeItem(off int, callerClass, callerMethod string) {
	data := f.data
	// code_item layout:
	//   uint16 registers_size (0)
	//   uint16 ins_size       (2)
	//   uint16 outs_size      (4)
	//   uint16 tries_size     (6)
	//   uint32 debug_info_off (8)
	//   uint32 insns_size     (12) -- in 16-bit code units
	//   uint16[insns_size]    (16)
	if off+16 > len(data) {
		return
	}

	le := binary.LittleEndian
	insnsSize := le.Uint32(data[off+12 : off+16])
	insnsOff := off + 16
	insnsEnd := insnsOff + int(insnsSize)*2

	if insnsEnd > len(data) {
		return
	}

	f.scanInsns(data[insnsOff:insnsEnd], uint32(insnsOff), callerClass, callerMethod)
}

// scanInsns scans a bytecode instruction stream for invoke-* opcodes.
func (f *File) scanInsns(insns []byte, baseOff uint32, callerClass, callerMethod string) {
	le := binary.LittleEndian
	pos := 0
	for pos+3 < len(insns) {
		opcode := insns[pos]

		if isInvokeOp(opcode) {
			// Format 35c/3rc: the method index is in the second 16-bit unit.
			methodIdx := le.Uint16(insns[pos+2 : pos+4])
			if int(methodIdx) < len(f.methods) {
				m := f.methods[methodIdx]
				ref := f.resolveMethod(m)
				key := methodKey{
					className:  descriptorToInternal(ref.ClassName),
					methodName: ref.MethodName,
				}
				f.callIndex[key] = append(f.callIndex[key], CallSite{
					CallerClass:  callerClass,
					CallerMethod: callerMethod,
					Offset:       baseOff + uint32(pos),
					Target:       ref,
				})
			}
		}

		// Advance by instruction width.
		width := insnWidth(insns, pos)
		if width == 0 {
			break
		}
		pos += width
	}
}

func isInvokeOp(op byte) bool {
	switch op {
	case opInvokeVirtual, opInvokeSuper, opInvokeDirect, opInvokeStatic, opInvokeInterface,
		opInvokeVirtualRange, opInvokeSuperRange, opInvokeDirectRange, opInvokeStaticRange, opInvokeInterfaceRange:
		return true
	}
	return false
}

// insnWidth returns the byte width of the instruction at the given position.
// Returns 0 if the instruction cannot be decoded.
func insnWidth(insns []byte, pos int) int {
	if pos >= len(insns) {
		return 0
	}
	op := insns[pos]

	// Handle pseudo-instructions embedded as nop (0x00).
	if op == 0x00 && pos+1 < len(insns) {
		switch insns[pos+1] {
		case 0x01:
			return packedSwitchWidth(insns, pos)
		case 0x02:
			return sparseSwitchWidth(insns, pos)
		case 0x03:
			return fillArrayWidth(insns, pos)
		}
	}

	w := opcodeWidth[op]
	if w == 0 {
		return 2 // unknown opcode, assume minimum
	}
	return int(w)
}

// opcodeWidth maps each Dalvik opcode to its byte width.
// Reference: https://source.android.com/docs/core/runtime/dalvik-bytecode
//
//nolint:gochecknoglobals
var opcodeWidth = [256]byte{
	// 00: nop
	0x00: 2,
	// 01: move (12x)
	0x01: 2,
	// 02: move/from16 (22x)
	0x02: 4,
	// 03: move/16 (32x)
	0x03: 6,
	// 04: move-wide (12x)
	0x04: 2,
	// 05: move-wide/from16 (22x)
	0x05: 4,
	// 06: move-wide/16 (32x)
	0x06: 6,
	// 07: move-object (12x)
	0x07: 2,
	// 08: move-object/from16 (22x)
	0x08: 4,
	// 09: move-object/16 (32x)
	0x09: 6,
	// 0A-0D: move-result variants (11x)
	0x0A: 2, 0x0B: 2, 0x0C: 2, 0x0D: 2,
	// 0E: return-void (10x)
	0x0E: 2,
	// 0F-11: return variants (11x)
	0x0F: 2, 0x10: 2, 0x11: 2,
	// 12: const/4 (11n)
	0x12: 2,
	// 13: const/16 (21s)
	0x13: 4,
	// 14: const (31i)
	0x14: 6,
	// 15: const/high16 (21h)
	0x15: 4,
	// 16: const-wide/16 (21s)
	0x16: 4,
	// 17: const-wide/32 (31i)
	0x17: 6,
	// 18: const-wide (51l)
	0x18: 10,
	// 19: const-wide/high16 (21h)
	0x19: 4,
	// 1A: const-string (21c)
	0x1A: 4,
	// 1B: const-string/jumbo (31c)
	0x1B: 6,
	// 1C: const-class (21c)
	0x1C: 4,
	// 1D: monitor-enter (11x)
	0x1D: 2,
	// 1E: monitor-exit (11x)
	0x1E: 2,
	// 1F: check-cast (21c)
	0x1F: 4,
	// 20: instance-of (22c)
	0x20: 4,
	// 21: array-length (12x)
	0x21: 2,
	// 22: new-instance (21c)
	0x22: 4,
	// 23: new-array (22c)
	0x23: 4,
	// 24: filled-new-array (35c)
	0x24: 6,
	// 25: filled-new-array/range (3rc)
	0x25: 6,
	// 26: fill-array-data (31t)
	0x26: 6,
	// 27: throw (11x)
	0x27: 2,
	// 28: goto (10t)
	0x28: 2,
	// 29: goto/16 (20t)
	0x29: 4,
	// 2A: goto/32 (30t)
	0x2A: 6,
	// 2B: packed-switch (31t)
	0x2B: 6,
	// 2C: sparse-switch (31t)
	0x2C: 6,
	// 2D-31: cmpX (23x)
	0x2D: 4, 0x2E: 4, 0x2F: 4, 0x30: 4, 0x31: 4,
	// 32-37: if-test (22t)
	0x32: 4, 0x33: 4, 0x34: 4, 0x35: 4, 0x36: 4, 0x37: 4,
	// 38-3D: if-testz (21t)
	0x38: 4, 0x39: 4, 0x3A: 4, 0x3B: 4, 0x3C: 4, 0x3D: 4,
	// 3E-43: unused
	0x3E: 2, 0x3F: 2, 0x40: 2, 0x41: 2, 0x42: 2, 0x43: 2,
	// 44-51: aget/aput variants (23x)
	0x44: 4, 0x45: 4, 0x46: 4, 0x47: 4, 0x48: 4, 0x49: 4, 0x4A: 4,
	0x4B: 4, 0x4C: 4, 0x4D: 4, 0x4E: 4, 0x4F: 4, 0x50: 4, 0x51: 4,
	// 52-6D: iget/iput/sget/sput variants (22c)
	0x52: 4, 0x53: 4, 0x54: 4, 0x55: 4, 0x56: 4, 0x57: 4, 0x58: 4,
	0x59: 4, 0x5A: 4, 0x5B: 4, 0x5C: 4, 0x5D: 4, 0x5E: 4, 0x5F: 4,
	0x60: 4, 0x61: 4, 0x62: 4, 0x63: 4, 0x64: 4, 0x65: 4, 0x66: 4,
	0x67: 4, 0x68: 4, 0x69: 4, 0x6A: 4, 0x6B: 4, 0x6C: 4, 0x6D: 4,
	// 6E-72: invoke-kind (35c)
	0x6E: 6, 0x6F: 6, 0x70: 6, 0x71: 6, 0x72: 6,
	// 73: unused
	0x73: 2,
	// 74-78: invoke-kind/range (3rc)
	0x74: 6, 0x75: 6, 0x76: 6, 0x77: 6, 0x78: 6,
	// 79-7A: unused
	0x79: 2, 0x7A: 2,
	// 7B-8F: unop (12x)
	0x7B: 2, 0x7C: 2, 0x7D: 2, 0x7E: 2, 0x7F: 2,
	0x80: 2, 0x81: 2, 0x82: 2, 0x83: 2, 0x84: 2, 0x85: 2, 0x86: 2,
	0x87: 2, 0x88: 2, 0x89: 2, 0x8A: 2, 0x8B: 2, 0x8C: 2, 0x8D: 2,
	0x8E: 2, 0x8F: 2,
	// 90-AF: binop (23x)
	0x90: 4, 0x91: 4, 0x92: 4, 0x93: 4, 0x94: 4, 0x95: 4, 0x96: 4,
	0x97: 4, 0x98: 4, 0x99: 4, 0x9A: 4, 0x9B: 4, 0x9C: 4, 0x9D: 4,
	0x9E: 4, 0x9F: 4, 0xA0: 4, 0xA1: 4, 0xA2: 4, 0xA3: 4, 0xA4: 4,
	0xA5: 4, 0xA6: 4, 0xA7: 4, 0xA8: 4, 0xA9: 4, 0xAA: 4, 0xAB: 4,
	0xAC: 4, 0xAD: 4, 0xAE: 4, 0xAF: 4,
	// B0-CF: binop/2addr (12x)
	0xB0: 2, 0xB1: 2, 0xB2: 2, 0xB3: 2, 0xB4: 2, 0xB5: 2, 0xB6: 2,
	0xB7: 2, 0xB8: 2, 0xB9: 2, 0xBA: 2, 0xBB: 2, 0xBC: 2, 0xBD: 2,
	0xBE: 2, 0xBF: 2, 0xC0: 2, 0xC1: 2, 0xC2: 2, 0xC3: 2, 0xC4: 2,
	0xC5: 2, 0xC6: 2, 0xC7: 2, 0xC8: 2, 0xC9: 2, 0xCA: 2, 0xCB: 2,
	0xCC: 2, 0xCD: 2, 0xCE: 2, 0xCF: 2,
	// D0-D7: binop/lit16 (22s)
	0xD0: 4, 0xD1: 4, 0xD2: 4, 0xD3: 4, 0xD4: 4, 0xD5: 4, 0xD6: 4, 0xD7: 4,
	// D8-E2: binop/lit8 (22b)
	0xD8: 4, 0xD9: 4, 0xDA: 4, 0xDB: 4, 0xDC: 4, 0xDD: 4, 0xDE: 4,
	0xDF: 4, 0xE0: 4, 0xE1: 4, 0xE2: 4,
	// E3-FF: unused/extended
}

func packedSwitchWidth(insns []byte, pos int) int {
	if pos+8 > len(insns) {
		return 2
	}
	le := binary.LittleEndian
	size := int(le.Uint16(insns[pos+2 : pos+4]))
	return 2 + 4 + size*4 // ident(2) + size(2) + first_key(4) + targets(4*size)
}

func sparseSwitchWidth(insns []byte, pos int) int {
	if pos+4 > len(insns) {
		return 2
	}
	le := binary.LittleEndian
	size := int(le.Uint16(insns[pos+2 : pos+4]))
	return 2 + 2 + size*4 + size*4 // ident(2) + size(2) + keys(4*size) + targets(4*size)
}

func fillArrayWidth(insns []byte, pos int) int {
	if pos+8 > len(insns) {
		return 2
	}
	le := binary.LittleEndian
	elementWidth := int(le.Uint16(insns[pos+2 : pos+4]))
	numElements := int(le.Uint32(insns[pos+4 : pos+8]))
	dataBytes := elementWidth * numElements
	// Round up to 2-byte alignment.
	totalBytes := 8 + dataBytes
	if totalBytes%2 != 0 {
		totalBytes++
	}
	return totalBytes
}

// descriptorToInternal converts a JVM type descriptor (e.g. "Landroid/webkit/WebSettings;")
// to internal format ("android/webkit/WebSettings").
func descriptorToInternal(desc string) string {
	s := strings.TrimPrefix(desc, "L")
	s = strings.TrimSuffix(s, ";")
	return s
}
