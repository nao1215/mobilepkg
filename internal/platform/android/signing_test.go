package android

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// apkWithSigningFooter builds the smallest file findAPKSigningBlock reads: some
// padding, a signing block footer claiming blockSize, and an EOCD record whose
// central directory offset points right after that footer.
func apkWithSigningFooter(blockSize uint64) []byte {
	var b bytes.Buffer
	b.Write(make([]byte, 64))
	footer := make([]byte, 8)
	binary.LittleEndian.PutUint64(footer, blockSize)
	b.Write(footer)
	b.WriteString(apkSigBlockMagic)
	cdOffset := uint32(b.Len()) //nolint:gosec // a 88-byte test buffer
	eocd := make([]byte, 22)
	copy(eocd, []byte{0x50, 0x4b, 0x05, 0x06})
	binary.LittleEndian.PutUint32(eocd[16:20], cdOffset)
	b.Write(eocd)
	return b.Bytes()
}

func TestFindAPKSigningBlockRejectsOversizedBlockSize(t *testing.T) {
	t.Parallel()
	for _, size := range []uint64{1 << 63, ^uint64(0), 1 << 40} {
		data := apkWithSigningFooter(size)
		if _, err := findAPKSigningBlock(bytes.NewReader(data), int64(len(data))); err == nil {
			t.Errorf("block size %d: want an error, got none", size)
		}
	}
}

func TestFindAPKSigningBlockReadsBlockThatFits(t *testing.T) {
	t.Parallel()
	data := apkWithSigningFooter(40) // 16 bytes of pairs area + 24-byte footer
	block, err := findAPKSigningBlock(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if len(block) != 48 {
		t.Fatalf("block length = %d, want 48", len(block))
	}
}

func TestFindBlockByIDRejectsOversizedPairSize(t *testing.T) {
	t.Parallel()
	for _, size := range []uint64{1 << 63, ^uint64(0)} {
		block := make([]byte, 8+12+24)
		binary.LittleEndian.PutUint64(block[8:16], size)
		binary.LittleEndian.PutUint32(block[16:20], 0x7109871a)
		if _, err := findBlockByID(block, 0x7109871a); err == nil {
			t.Errorf("pair size %d: want an error, got none", size)
		}
	}
}
