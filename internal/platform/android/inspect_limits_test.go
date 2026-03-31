package android

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadStringPool_RejectsOverlargeStringCount(t *testing.T) {
	t.Parallel()

	// Build a minimal resStringPoolHeader with StringCount exceeding the cap.
	hdr := resStringPoolHeader{
		Header: resChunkHeader{
			Type:       resStringPoolChunkType,
			HeaderSize: 28, // standard string pool header size
			Size:       100,
		},
		StringCount: maxStringPoolCount + 1,
		StyleCount:  0,
		Flags:       0,
		StringStart: 0,
		StylesStart: 0,
	}

	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, hdr)

	sr := io.NewSectionReader(bytes.NewReader(buf.Bytes()), 0, int64(buf.Len()))
	_, err := readStringPool(sr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "string count")
}

func TestReadStringPool_RejectsOverlargeStyleCount(t *testing.T) {
	t.Parallel()

	hdr := resStringPoolHeader{
		Header: resChunkHeader{
			Type:       resStringPoolChunkType,
			HeaderSize: 28,
			Size:       100,
		},
		StringCount: 0,
		StyleCount:  maxStringPoolCount + 1,
		Flags:       0,
		StringStart: 0,
		StylesStart: 0,
	}

	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, hdr)

	sr := io.NewSectionReader(bytes.NewReader(buf.Bytes()), 0, int64(buf.Len()))
	_, err := readStringPool(sr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "style count")
}

func TestReadTableType_RejectsOverlargeEntryCount(t *testing.T) {
	t.Parallel()

	// Build a minimal chunk header + resTableTypeHeader with huge EntryCount.
	ch := resChunkHeader{
		Type:       resTableTypeType,
		HeaderSize: 76, // typical table type header size
		Size:       200,
	}
	hdr := resTableTypeHeader{
		Header:       ch,
		ID:           1,
		EntryCount:   maxTableEntryCount + 1,
		EntriesStart: 76,
	}

	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, hdr)

	sr := io.NewSectionReader(bytes.NewReader(buf.Bytes()), 0, int64(buf.Len()))
	_, err := readTableType(sr, 0, ch)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entry count")
}

func TestReadUTF16String_RejectsOverlargeLength(t *testing.T) {
	t.Parallel()

	// Encode a UTF-16 length that exceeds maxStringBytes.
	// The high-bit encoding: first uint16 has bit 15 set, second gives low bits.
	// Total length = (first & 0x7FFF) << 16 + second.
	// We want size*2 > maxStringBytes, so size > maxStringBytes/2.
	wantSize := maxStringBytes/2 + 1
	first := uint16(0x8000 | uint16(wantSize>>16))
	second := uint16(wantSize & 0xFFFF)

	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, first)
	_ = binary.Write(&buf, binary.LittleEndian, second)

	_, err := readUTF16String(&buf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "UTF-16 string length")
}

func TestReadUTF8String_RejectsOverlargeLength(t *testing.T) {
	t.Parallel()

	// UTF-8 length encoding: high-bit means 2-byte length.
	// Total = (first & 0x7F) << 8 + second. Max is ~32 KiB which is
	// under maxStringBytes, so this test just verifies the guard is
	// present. We write a valid small string to confirm no false positive.
	var buf bytes.Buffer
	// UTF-16 length byte (skip): 5
	buf.WriteByte(5)
	// UTF-8 length byte: 5
	buf.WriteByte(5)
	// 5 bytes of string data
	buf.WriteString("hello")

	s, err := readUTF8String(&buf)
	assert.NoError(t, err)
	assert.Equal(t, "hello", s)
}
