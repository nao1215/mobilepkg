package dex

import (
	"encoding/binary"
	"fmt"
)

// maxStringIDsCount is a safety limit to prevent allocation of unreasonably
// large slices from malformed DEX files.
const maxStringIDsCount = 5_000_000

func (f *File) parseStringIDs(data []byte) error {
	h := f.header
	count := int(h.StringIDsSize)
	if count == 0 {
		return nil
	}
	if count > maxStringIDsCount {
		return fmt.Errorf("string_ids count %d exceeds safety limit %d", count, maxStringIDsCount)
	}

	off := int(h.StringIDsOff)
	end := off + count*4
	if end > len(data) || off > len(data) {
		return fmt.Errorf("string_ids table (offset=%d, count=%d) exceeds file size %d", off, count, len(data))
	}

	le := binary.LittleEndian
	f.strings = make([]string, count)
	// string_data_items never overlap in a well-formed DEX, so the bytes they
	// occupy add up to at most the file size. Enforcing that keeps a crafted
	// string_ids table (many entries pointing into one long run of bytes)
	// from decoding the same data over and over into gigabytes of strings.
	// Entries that repeat an offset share the already decoded string.
	seen := make(map[int]string)
	consumed := 0
	for i := range count {
		strDataOff := int(le.Uint32(data[off+i*4 : off+i*4+4]))
		if s, ok := seen[strDataOff]; ok {
			f.strings[i] = s
			continue
		}
		s, n, err := readMUTF8(data, strDataOff)
		if err != nil {
			return fmt.Errorf("string %d at offset %d: %w", i, strDataOff, err)
		}
		consumed += n
		if consumed > len(data) {
			return fmt.Errorf("string data items overlap: %d bytes decoded from a %d-byte file", consumed, len(data))
		}
		seen[strDataOff] = s
		f.strings[i] = s
	}
	return nil
}

// readMUTF8 reads a MUTF-8 encoded string from data at the given offset.
// The format is: ULEB128 character count, followed by MUTF-8 bytes, followed
// by a zero byte terminator. It also returns the number of bytes the item
// occupies, terminator included.
func readMUTF8(data []byte, off int) (string, int, error) {
	if off < 0 || off >= len(data) {
		return "", 0, fmt.Errorf("offset %d out of bounds (size %d)", off, len(data))
	}

	// Read ULEB128 character count (we skip it; read until null terminator).
	_, n, err := readULEB128(data, off)
	if err != nil {
		return "", 0, err
	}
	start := off + n

	// Read MUTF-8 bytes until null terminator.
	end := start
	for end < len(data) && data[end] != 0 {
		end++
	}
	size := end - off
	if end < len(data) {
		size++ // terminator
	}
	return decodeMUTF8(data[start:end]), size, nil
}

// decodeMUTF8 decodes MUTF-8 encoded bytes to a Go string.
// MUTF-8 is similar to CESU-8 with null encoded as 0xC0 0x80.
func decodeMUTF8(data []byte) string {
	var runes []rune
	i := 0
	for i < len(data) {
		b := data[i]
		switch {
		case b == 0xC0 && i+1 < len(data) && data[i+1] == 0x80:
			// Encoded null.
			runes = append(runes, 0)
			i += 2
		case b&0x80 == 0:
			// Single byte (ASCII).
			runes = append(runes, rune(b))
			i++
		case b&0xE0 == 0xC0:
			// Two-byte sequence.
			if i+1 >= len(data) {
				runes = append(runes, rune(b))
				i++
				continue
			}
			r := rune(b&0x1F)<<6 | rune(data[i+1]&0x3F)
			runes = append(runes, r)
			i += 2
		case b&0xF0 == 0xE0:
			// Three-byte sequence.
			if i+2 >= len(data) {
				runes = append(runes, rune(b))
				i++
				continue
			}
			r := rune(b&0x0F)<<12 | rune(data[i+1]&0x3F)<<6 | rune(data[i+2]&0x3F)
			runes = append(runes, r)
			i += 3
		default:
			runes = append(runes, rune(b))
			i++
		}
	}
	return string(runes)
}

// readULEB128 reads an unsigned LEB128 value from data at the given offset.
// Returns the value and the number of bytes consumed.
func readULEB128(data []byte, off int) (uint32, int, error) {
	var result uint32
	var shift uint
	pos := off
	for {
		if pos >= len(data) {
			return 0, 0, fmt.Errorf("ULEB128 at offset %d extends beyond data", off)
		}
		b := data[pos]
		result |= uint32(b&0x7F) << shift
		pos++
		if b&0x80 == 0 {
			break
		}
		shift += 7
		if shift >= 35 {
			return 0, 0, fmt.Errorf("ULEB128 at offset %d is too large", off)
		}
	}
	return result, pos - off, nil
}
