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
