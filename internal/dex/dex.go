// Package dex provides a minimal parser for Android DEX (Dalvik Executable)
// files. It extracts string tables, method references, class definitions, and
// scans bytecode for method invocations. This is not a full DEX interpreter;
// it provides enough structure for static security analysis.
package dex

import (
	"encoding/binary"
	"fmt"
)

// dexMagicPrefix is the expected prefix for DEX file magic bytes.
var dexMagicPrefix = []byte("dex\n")

// headerSize is the fixed size of a DEX file header.
const headerSize = 0x70

// endianConstant is the expected little-endian tag in the DEX header.
const endianConstant = 0x12345678

// File represents a parsed DEX file.
type File struct {
	header  header
	strings []string
	types   []string // resolved type descriptors
	protos  []ProtoID
	fields  []FieldID
	methods []MethodID
	classes []ClassDef
	data    []byte // raw file data retained for instruction scanning

	// callIndex is a lazily built inverted index of method calls.
	callIndex map[methodKey][]CallSite
}

type header struct {
	Magic         [8]byte
	Checksum      uint32
	Signature     [20]byte
	FileSize      uint32
	HeaderSize    uint32
	EndianTag     uint32
	LinkSize      uint32
	LinkOff       uint32
	MapOff        uint32
	StringIDsSize uint32
	StringIDsOff  uint32
	TypeIDsSize   uint32
	TypeIDsOff    uint32
	ProtoIDsSize  uint32
	ProtoIDsOff   uint32
	FieldIDsSize  uint32
	FieldIDsOff   uint32
	MethodIDsSize uint32
	MethodIDsOff  uint32
	ClassDefsSize uint32
	ClassDefsOff  uint32
	DataSize      uint32
	DataOff       uint32
}

// ProtoID represents a method prototype in the DEX file.
type ProtoID struct {
	ShortyIdx     uint32
	ReturnTypeIdx uint32
	ParametersOff uint32
}

// FieldID represents a field reference in the DEX file.
type FieldID struct {
	ClassIdx uint16
	TypeIdx  uint16
	NameIdx  uint32
}

// MethodID represents a method reference in the DEX file.
type MethodID struct {
	ClassIdx uint16
	ProtoIdx uint16
	NameIdx  uint32
}

// ClassDef represents a class definition in the DEX file.
type ClassDef struct {
	ClassIdx        uint32
	AccessFlags     uint32
	SuperclassIdx   uint32
	InterfacesOff   uint32
	SourceFileIdx   uint32
	AnnotationsOff  uint32
	ClassDataOff    uint32
	StaticValuesOff uint32
}

// MethodRef is the resolved representation of a method reference.
type MethodRef struct {
	ClassName  string
	MethodName string
	ProtoDesc  string // shorty descriptor
}

// CallSite represents a location where a method is invoked.
type CallSite struct {
	CallerClass  string
	CallerMethod string
	Offset       uint32 // byte offset within the DEX file
	Target       MethodRef
}

// methodKey is used as a map key for the call index.
type methodKey struct {
	className  string
	methodName string
}

// RawData returns the raw DEX file bytes for low-level instruction analysis.
// The returned slice is shared with the File; callers must not modify it.
func (f *File) RawData() []byte {
	return f.data
}

// Strings returns all strings from the DEX string table.
func (f *File) Strings() []string {
	return f.strings
}

// Methods returns all resolved method references.
func (f *File) Methods() []MethodRef {
	refs := make([]MethodRef, len(f.methods))
	for i, m := range f.methods {
		refs[i] = f.resolveMethod(m)
	}
	return refs
}

// Classes returns all class definitions.
func (f *File) Classes() []ClassDef {
	return f.classes
}

// FindMethodCalls returns all call sites where the given class and method
// are invoked. The className should use JVM internal format with slashes
// (e.g. "android/webkit/WebSettings"). An empty className matches any class.
func (f *File) FindMethodCalls(className, methodName string) []CallSite {
	f.ensureCallIndex()
	return f.callIndex[methodKey{className: className, methodName: methodName}]
}

func (f *File) resolveMethod(m MethodID) MethodRef {
	ref := MethodRef{}
	if int(m.ClassIdx) < len(f.types) {
		ref.ClassName = f.types[m.ClassIdx]
	}
	if int(m.NameIdx) < len(f.strings) {
		ref.MethodName = f.strings[m.NameIdx]
	}
	if int(m.ProtoIdx) < len(f.protos) {
		p := f.protos[m.ProtoIdx]
		if int(p.ShortyIdx) < len(f.strings) {
			ref.ProtoDesc = f.strings[p.ShortyIdx]
		}
	}
	return ref
}

func (f *File) resolveType(idx uint32) string {
	if int(idx) < len(f.types) {
		return f.types[idx]
	}
	return ""
}

// Parse parses a DEX file from the given byte slice.
func Parse(data []byte) (*File, error) {
	if len(data) < headerSize {
		return nil, fmt.Errorf("dex: file too small (%d bytes, minimum %d)", len(data), headerSize)
	}

	var h header
	if err := parseHeader(data, &h); err != nil {
		return nil, err
	}

	f := &File{
		header: h,
		data:   data,
	}

	if err := f.parseStringIDs(data); err != nil {
		return nil, fmt.Errorf("dex: string_ids: %w", err)
	}
	if err := f.parseTypeIDs(data); err != nil {
		return nil, fmt.Errorf("dex: type_ids: %w", err)
	}
	if err := f.parseProtoIDs(data); err != nil {
		return nil, fmt.Errorf("dex: proto_ids: %w", err)
	}
	if err := f.parseFieldIDs(data); err != nil {
		return nil, fmt.Errorf("dex: field_ids: %w", err)
	}
	if err := f.parseMethodIDs(data); err != nil {
		return nil, fmt.Errorf("dex: method_ids: %w", err)
	}
	if err := f.parseClassDefs(data); err != nil {
		return nil, fmt.Errorf("dex: class_defs: %w", err)
	}

	return f, nil
}

func parseHeader(data []byte, h *header) error {
	// Validate magic.
	if len(data) < 4 || string(data[:4]) != string(dexMagicPrefix) {
		return fmt.Errorf("dex: invalid magic bytes")
	}

	le := binary.LittleEndian

	copy(h.Magic[:], data[:8])
	h.Checksum = le.Uint32(data[8:12])
	copy(h.Signature[:], data[12:32])
	h.FileSize = le.Uint32(data[32:36])
	h.HeaderSize = le.Uint32(data[36:40])
	h.EndianTag = le.Uint32(data[40:44])

	if h.EndianTag != endianConstant {
		return fmt.Errorf("dex: unsupported endian tag 0x%08x (expected 0x%08x)", h.EndianTag, endianConstant)
	}

	h.LinkSize = le.Uint32(data[44:48])
	h.LinkOff = le.Uint32(data[48:52])
	h.MapOff = le.Uint32(data[52:56])
	h.StringIDsSize = le.Uint32(data[56:60])
	h.StringIDsOff = le.Uint32(data[60:64])
	h.TypeIDsSize = le.Uint32(data[64:68])
	h.TypeIDsOff = le.Uint32(data[68:72])
	h.ProtoIDsSize = le.Uint32(data[72:76])
	h.ProtoIDsOff = le.Uint32(data[76:80])
	h.FieldIDsSize = le.Uint32(data[80:84])
	h.FieldIDsOff = le.Uint32(data[84:88])
	h.MethodIDsSize = le.Uint32(data[88:92])
	h.MethodIDsOff = le.Uint32(data[92:96])
	h.ClassDefsSize = le.Uint32(data[96:100])
	h.ClassDefsOff = le.Uint32(data[100:104])
	h.DataSize = le.Uint32(data[104:108])
	h.DataOff = le.Uint32(data[108:112])

	return nil
}
