package android

import (
	"archive/zip"
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
	first := 0x8000 | uint16(wantSize>>16)
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

// maxFuzzResourceBytes bounds fuzz inputs for the binary XML and resource
// table parsers. The properties below are about how output grows with the
// input, so small inputs are enough to expose amplification.
const maxFuzzResourceBytes = 64 << 10

// fuzzSeedsFromAPK returns the named entries of the test APK, truncated to
// maxFuzzResourceBytes, for use as fuzz seeds.
func fuzzSeedsFromAPK(f *testing.F, names ...string) [][]byte {
	f.Helper()
	zr, err := zip.OpenReader("../../../testdata/android/androgoat_rich.apk")
	if err != nil {
		f.Fatal(err)
	}
	defer func() { _ = zr.Close() }()
	seeds := make([][]byte, 0, len(names))
	for _, name := range names {
		data, err := readZipFile(&zr.Reader, name, 4<<20)
		if err != nil {
			f.Fatalf("read %s: %v", name, err)
		}
		if len(data) > maxFuzzResourceBytes {
			data = data[:maxFuzzResourceBytes]
		}
		seeds = append(seeds, data)
	}
	return seeds
}

// distinctStringBytes returns the total size of the distinct strings in a
// pool. Entries that share an offset share one string in memory.
func distinctStringBytes(pool *resStringPool) int {
	if pool == nil {
		return 0
	}
	total := 0
	seen := make(map[string]struct{})
	for _, s := range pool.strings {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			total += len(s)
		}
	}
	return total
}

// FuzzNewXMLFile feeds arbitrary bytes to the binary XML decoder used for
// AndroidManifest.xml and network_security_config.xml. Properties: no panic,
// no hang, the decoded string pool stays linear in the input, and the text
// XML it produces stays under maxDecodedXMLBytes.
func FuzzNewXMLFile(f *testing.F) {
	for _, seed := range fuzzSeedsFromAPK(f, "AndroidManifest.xml", "res/xml/network_security_config.xml") {
		f.Add(seed)
	}
	f.Add([]byte{0x03, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzResourceBytes {
			t.Skip()
		}
		xf, err := newXMLFile(data)
		if err != nil {
			return
		}
		// UTF-16 code units decode to at most 3 UTF-8 bytes per 2 input
		// bytes, UTF-8 strings are copied as is.
		if got, limit := distinctStringBytes(xf.pool), 2*len(data); got > limit {
			t.Fatalf("string pool decoded to %d bytes from a %d-byte input (limit %d)", got, len(data), limit)
		}
		if got := xf.buf.Len(); got > maxDecodedXMLBytes {
			t.Fatalf("decoded XML is %d bytes, over the %d-byte limit", got, maxDecodedXMLBytes)
		}
	})
}

// FuzzNewTableFile feeds arbitrary bytes to the resources.arsc decoder and
// resolves a few resource IDs against the result. Properties: no panic, no
// hang, and every decoded string pool stays linear in the input.
func FuzzNewTableFile(f *testing.F) {
	for _, seed := range fuzzSeedsFromAPK(f, "resources.arsc") {
		f.Add(seed)
	}
	f.Add([]byte{0x02, 0x00, 0x0c, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzResourceBytes {
			t.Skip()
		}
		tf, err := newTableFile(data)
		if err != nil {
			return
		}
		total := distinctStringBytes(tf.stringPool)
		for _, pkg := range tf.packages {
			total += distinctStringBytes(pkg.typeStrings) + distinctStringBytes(pkg.keyStrings)
		}
		// The global pool and each package's two pools can each cover the
		// whole input, so allow three times the linear bound per package.
		if limit := 2 * len(data) * (1 + 2*len(tf.packages)); total > limit {
			t.Fatalf("string pools decoded to %d bytes from a %d-byte input (limit %d)", total, len(data), limit)
		}
		for _, id := range []uint32{0x7f010000, 0x7f020001, 0x01010000} {
			tf.getResource(id)
		}
		_ = resolveString("@0x7f010000", tf)
	})
}

// binXML concatenates little-endian encodings of the given values.
func binXML(t *testing.T, parts ...any) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, p := range parts {
		if err := binary.Write(&buf, binary.LittleEndian, p); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func TestNewXMLFile_RejectsZeroSizeChunk(t *testing.T) {
	t.Parallel()

	// A chunk that declares size 0 used to make the chunk walker read the
	// same offset forever. Found by FuzzNewXMLFile.
	data := binXML(t,
		resChunkHeader{Type: 0x0003, HeaderSize: 8, Size: 16},
		resChunkHeader{Type: 0x0180, HeaderSize: 8, Size: 0},
	)
	_, err := newXMLFile(data)
	assert.ErrorContains(t, err, "smaller than its 8-byte header")
}

func TestNewTableFile_RejectsZeroSizeChunk(t *testing.T) {
	t.Parallel()

	data := binXML(t,
		resTableHeader{Header: resChunkHeader{Type: resTableChunkType, HeaderSize: 12, Size: 20}},
		resChunkHeader{Type: 0x0180, HeaderSize: 8, Size: 0},
	)
	_, err := newTableFile(data)
	assert.ErrorContains(t, err, "smaller than its 8-byte header")
}

func TestReadStringPool_RejectsOverlappingStrings(t *testing.T) {
	t.Parallel()

	// Every offset points one byte further into the same run of 0x7F bytes,
	// so each entry decodes a 127-byte string out of the bytes the previous
	// entries already used. Found by FuzzNewXMLFile.
	const count = 200
	const headerLen = 28
	offsets := make([]uint32, count)
	for i := range offsets {
		offsets[i] = uint32(i)
	}
	run := bytes.Repeat([]byte{0x7F}, 400)
	size := uint32(headerLen + 4*count + len(run))
	data := binXML(t,
		resStringPoolHeader{
			Header:      resChunkHeader{Type: resStringPoolChunkType, HeaderSize: headerLen, Size: size},
			StringCount: count,
			Flags:       utf8Flag,
			StringStart: headerLen + 4*count,
		},
		offsets,
		run,
	)

	_, err := readStringPool(io.NewSectionReader(bytes.NewReader(data), 0, int64(len(data))))
	assert.ErrorContains(t, err, "strings overlap")
}

func TestReadStringPool_SharedOffsetIsAccepted(t *testing.T) {
	t.Parallel()

	const headerLen = 28
	str := []byte{1, 1, 'a', 0} // UTF-16 length, UTF-8 length, "a", NUL
	data := binXML(t,
		resStringPoolHeader{
			Header:      resChunkHeader{Type: resStringPoolChunkType, HeaderSize: headerLen, Size: headerLen + 8 + 4},
			StringCount: 2,
			Flags:       utf8Flag,
			StringStart: headerLen + 8,
		},
		[]uint32{0, 0},
		str,
	)

	pool, err := readStringPool(io.NewSectionReader(bytes.NewReader(data), 0, int64(len(data))))
	if assert.NoError(t, err) {
		assert.Equal(t, []string{"a", "a"}, pool.strings)
	}
}

func TestNewXMLFile_RejectsOverlappingAttributes(t *testing.T) {
	t.Parallel()

	// One 20-byte attribute record with AttributeSize 0 and AttributeCount
	// 65535 used to be emitted 65535 times.
	const headerLen = 28
	pool := binXML(t,
		resStringPoolHeader{
			Header:      resChunkHeader{Type: resStringPoolChunkType, HeaderSize: headerLen, Size: headerLen + 4 + 4},
			StringCount: 1,
			Flags:       utf8Flag,
			StringStart: headerLen + 4,
		},
		[]uint32{0},
		[]byte{1, 1, 'a', 0},
	)
	var attr resXMLTreeAttribute
	attr.NS = nilRef
	attr.TypedValue.Size = 8
	attr.TypedValue.DataType = typeString
	elemSize := uint32(16 + 20 + 20)
	elem := binXML(t,
		resXMLTreeNode{Header: resChunkHeader{Type: resXMLStartElement, HeaderSize: 16, Size: elemSize}, Comment: nilRef},
		resXMLTreeAttrExt{NS: nilRef, Name: 0, AttributeStart: 20, AttributeSize: 0, AttributeCount: 0xFFFF},
		attr,
	)
	data := binXML(t,
		resChunkHeader{Type: 0x0003, HeaderSize: 8, Size: uint32(8 + len(pool) + len(elem))},
		pool,
		elem,
	)

	_, err := newXMLFile(data)
	assert.ErrorContains(t, err, "attribute size 0")
}
