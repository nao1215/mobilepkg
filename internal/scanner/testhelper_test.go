package scanner

import (
	"encoding/binary"
	"testing"
)

const testHeaderSize = 0x70
const testEndianConstant = 0x12345678

// buildMinDEX builds a minimal valid DEX file containing the given strings.
func buildMinDEX(t *testing.T, strings []string) []byte {
	t.Helper()

	le := binary.LittleEndian

	headerBytes := make([]byte, testHeaderSize)

	// String IDs
	stringIDsOff := testHeaderSize
	stringIDsSize := len(strings)
	stringIDsBytes := make([]byte, stringIDsSize*4)

	// String data section
	dataOff := stringIDsOff + len(stringIDsBytes)
	var stringDataBytes []byte
	for i, s := range strings {
		off := dataOff + len(stringDataBytes)
		le.PutUint32(stringIDsBytes[i*4:], uint32(off))
		stringDataBytes = testAppendULEB128(stringDataBytes, uint32(len(s)))
		stringDataBytes = append(stringDataBytes, []byte(s)...)
		stringDataBytes = append(stringDataBytes, 0)
	}

	fileSize := dataOff + len(stringDataBytes)

	// Fill header.
	copy(headerBytes[0:8], "dex\n035\x00")
	le.PutUint32(headerBytes[32:36], uint32(fileSize))
	le.PutUint32(headerBytes[36:40], testHeaderSize)
	le.PutUint32(headerBytes[40:44], testEndianConstant)
	le.PutUint32(headerBytes[56:60], uint32(stringIDsSize))
	le.PutUint32(headerBytes[60:64], uint32(stringIDsOff))
	// All other section sizes/offsets stay 0.
	le.PutUint32(headerBytes[104:108], uint32(len(stringDataBytes)))
	le.PutUint32(headerBytes[108:112], uint32(dataOff))

	out := make([]byte, 0, len(headerBytes)+len(stringIDsBytes)+len(stringDataBytes))
	out = append(out, headerBytes...)
	out = append(out, stringIDsBytes...)
	out = append(out, stringDataBytes...)
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
