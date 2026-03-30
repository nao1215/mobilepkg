package dex

import (
	"encoding/binary"
	"fmt"
)

// Safety limits for section counts to prevent huge allocations from
// malformed headers.
const (
	maxTypeIDsCount   = 1_000_000
	maxProtoIDsCount  = 1_000_000
	maxFieldIDsCount  = 5_000_000
	maxMethodIDsCount = 5_000_000
	maxClassDefsCount = 1_000_000
)

func (f *File) parseTypeIDs(data []byte) error {
	h := f.header
	count := int(h.TypeIDsSize)
	if count == 0 {
		return nil
	}
	if count > maxTypeIDsCount {
		return fmt.Errorf("type_ids count %d exceeds safety limit %d", count, maxTypeIDsCount)
	}

	off := int(h.TypeIDsOff)
	end := off + count*4
	if end > len(data) || off > len(data) {
		return fmt.Errorf("type_ids table (offset=%d, count=%d) exceeds file size %d", off, count, len(data))
	}

	le := binary.LittleEndian
	f.types = make([]string, count)
	for i := range count {
		strIdx := le.Uint32(data[off+i*4 : off+i*4+4])
		if int(strIdx) < len(f.strings) {
			f.types[i] = f.strings[strIdx]
		}
	}
	return nil
}

func (f *File) parseProtoIDs(data []byte) error {
	h := f.header
	count := int(h.ProtoIDsSize)
	if count == 0 {
		return nil
	}
	if count > maxProtoIDsCount {
		return fmt.Errorf("proto_ids count %d exceeds safety limit %d", count, maxProtoIDsCount)
	}

	off := int(h.ProtoIDsOff)
	// Each proto_id is 12 bytes.
	end := off + count*12
	if end > len(data) || off > len(data) {
		return fmt.Errorf("proto_ids table (offset=%d, count=%d) exceeds file size %d", off, count, len(data))
	}

	le := binary.LittleEndian
	f.protos = make([]ProtoID, count)
	for i := range count {
		base := off + i*12
		f.protos[i] = ProtoID{
			ShortyIdx:     le.Uint32(data[base : base+4]),
			ReturnTypeIdx: le.Uint32(data[base+4 : base+8]),
			ParametersOff: le.Uint32(data[base+8 : base+12]),
		}
	}
	return nil
}

func (f *File) parseFieldIDs(data []byte) error {
	h := f.header
	count := int(h.FieldIDsSize)
	if count == 0 {
		return nil
	}
	if count > maxFieldIDsCount {
		return fmt.Errorf("field_ids count %d exceeds safety limit %d", count, maxFieldIDsCount)
	}

	off := int(h.FieldIDsOff)
	// Each field_id is 8 bytes.
	end := off + count*8
	if end > len(data) || off > len(data) {
		return fmt.Errorf("field_ids table (offset=%d, count=%d) exceeds file size %d", off, count, len(data))
	}

	le := binary.LittleEndian
	f.fields = make([]FieldID, count)
	for i := range count {
		base := off + i*8
		f.fields[i] = FieldID{
			ClassIdx: le.Uint16(data[base : base+2]),
			TypeIdx:  le.Uint16(data[base+2 : base+4]),
			NameIdx:  le.Uint32(data[base+4 : base+8]),
		}
	}
	return nil
}

func (f *File) parseMethodIDs(data []byte) error {
	h := f.header
	count := int(h.MethodIDsSize)
	if count == 0 {
		return nil
	}
	if count > maxMethodIDsCount {
		return fmt.Errorf("method_ids count %d exceeds safety limit %d", count, maxMethodIDsCount)
	}

	off := int(h.MethodIDsOff)
	// Each method_id is 8 bytes.
	end := off + count*8
	if end > len(data) || off > len(data) {
		return fmt.Errorf("method_ids table (offset=%d, count=%d) exceeds file size %d", off, count, len(data))
	}

	le := binary.LittleEndian
	f.methods = make([]MethodID, count)
	for i := range count {
		base := off + i*8
		f.methods[i] = MethodID{
			ClassIdx: le.Uint16(data[base : base+2]),
			ProtoIdx: le.Uint16(data[base+2 : base+4]),
			NameIdx:  le.Uint32(data[base+4 : base+8]),
		}
	}
	return nil
}

func (f *File) parseClassDefs(data []byte) error {
	h := f.header
	count := int(h.ClassDefsSize)
	if count == 0 {
		return nil
	}
	if count > maxClassDefsCount {
		return fmt.Errorf("class_defs count %d exceeds safety limit %d", count, maxClassDefsCount)
	}

	off := int(h.ClassDefsOff)
	// Each class_def is 32 bytes.
	end := off + count*32
	if end > len(data) || off > len(data) {
		return fmt.Errorf("class_defs table (offset=%d, count=%d) exceeds file size %d", off, count, len(data))
	}

	le := binary.LittleEndian
	f.classes = make([]ClassDef, count)
	for i := range count {
		base := off + i*32
		f.classes[i] = ClassDef{
			ClassIdx:        le.Uint32(data[base : base+4]),
			AccessFlags:     le.Uint32(data[base+4 : base+8]),
			SuperclassIdx:   le.Uint32(data[base+8 : base+12]),
			InterfacesOff:   le.Uint32(data[base+12 : base+16]),
			SourceFileIdx:   le.Uint32(data[base+16 : base+20]),
			AnnotationsOff:  le.Uint32(data[base+20 : base+24]),
			ClassDataOff:    le.Uint32(data[base+24 : base+28]),
			StaticValuesOff: le.Uint32(data[base+28 : base+32]),
		}
	}
	return nil
}
