package android

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"image"
	"io"
	"strings"

	// Register image decoders for icon extraction.
	_ "image/jpeg"
	_ "image/png"
)

// Sentinel errors for Android inspection failures.
var (
	// ErrManifestNotFound indicates that AndroidManifest.xml is missing.
	ErrManifestNotFound = errors.New("android: AndroidManifest.xml not found in archive")
	// ErrManifestParseFailed indicates that AndroidManifest.xml could not be parsed.
	ErrManifestParseFailed = errors.New("android: failed to parse AndroidManifest.xml")
)

// Result holds the extracted data from an Android APK.
type Result struct {
	PackageName  string
	Label        string
	VersionName  string
	VersionCode  string
	MainActivity string
	Permissions  []string
	MinSDK       string
	TargetSDK    string
	Signing      *SigningResult
	IconPath     string
	IconBytes    []byte
	IconWidth    int
	IconHeight   int
	IconFormat   string
	RawManifest  map[string]any
}

// Inspect extracts information from an APK ZIP archive.
// The sections parameter is a bitmask controlling which data to extract.
// Bit positions match the mobilepkg.Section constants:
//
//	bit 0: Identity, bit 1: Version, bit 2: EntryPoint,
//	bit 3: Permissions, bit 4: Icon, bit 5: PlatformRaw,
//	bit 6: SDK, bit 7: Signing
//
// r and size are the underlying io.ReaderAt for the APK file, used for
// V2/V3 signing block extraction. They may be nil if signing is not requested.
func Inspect(zr *zip.Reader, sections uint64, r io.ReaderAt, size int64) (*Result, []Diagnostic, error) {
	manifestData, err := readZipFile(zr, "AndroidManifest.xml")
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrManifestNotFound, err)
	}

	var resourceTable *tableFile
	resData, resErr := readZipFile(zr, "resources.arsc")
	if resErr == nil {
		resourceTable, _ = newTableFile(bytes.NewReader(resData))
	}

	xmlFile, err := newXMLFile(bytes.NewReader(manifestData))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrManifestParseFailed, err)
	}

	var manifest manifest
	dec := xml.NewDecoder(xmlFile.reader())
	if err := dec.Decode(&manifest); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrManifestParseFailed, err)
	}

	if resourceTable != nil {
		injectTable(&manifest, resourceTable)
	}

	result := &Result{}
	var diags []Diagnostic

	const (
		bitIdentity    = 0
		bitVersion     = 1
		bitEntryPoint  = 2
		bitPermissions = 3
		bitIcon        = 4
		bitPlatformRaw = 5
		bitSDK         = 6
		bitSigning     = 7
	)

	// Identity
	if sections&(1<<bitIdentity) != 0 {
		result.PackageName = manifest.Package
		result.Label = resolveString(manifest.App.Label, resourceTable)
	}

	// Version
	if sections&(1<<bitVersion) != 0 {
		result.VersionName = manifest.VersionName
		result.VersionCode = manifest.VersionCode
	}

	// EntryPoint
	if sections&(1<<bitEntryPoint) != 0 {
		result.MainActivity = findMainActivity(manifest)
	}

	// Permissions
	if sections&(1<<bitPermissions) != 0 {
		for _, p := range manifest.UsesPermissions {
			result.Permissions = append(result.Permissions, p.Name)
		}
	}

	// Icon
	if sections&(1<<bitIcon) != 0 {
		iconPath := resolveString(manifest.App.Icon, resourceTable)
		if iconPath != "" && !strings.HasPrefix(iconPath, "@0x") {
			result.IconPath = iconPath
			data, readErr := readZipFile(zr, iconPath)
			if readErr == nil {
				result.IconBytes = data
				result.IconFormat = detectImageFormat(iconPath)
				img, _, decErr := image.Decode(bytes.NewReader(data))
				if decErr == nil {
					bounds := img.Bounds()
					result.IconWidth = bounds.Dx()
					result.IconHeight = bounds.Dy()
				}
			} else {
				diags = append(diags, Diagnostic{
					Code:     "icon.read_failed",
					Severity: "warn",
					Message:  fmt.Sprintf("failed to read icon %s: %v", iconPath, readErr),
				})
			}
		} else {
			diags = append(diags, Diagnostic{
				Code:     "icon.not_resolved",
				Severity: "warn",
				Message:  "icon path is a resource reference that could not be resolved",
			})
		}
	}

	// PlatformRaw
	if sections&(1<<bitPlatformRaw) != 0 {
		result.RawManifest = map[string]any{
			"package":     manifest.Package,
			"versionCode": manifest.VersionCode,
			"versionName": manifest.VersionName,
		}
	}

	// SDK constraints
	if sections&(1<<bitSDK) != 0 {
		result.MinSDK = manifest.UsesSdk.MinSdkVersion
		result.TargetSDK = manifest.UsesSdk.TargetSdkVersion
	}

	// Signing
	if sections&(1<<bitSigning) != 0 && r != nil {
		sigInfo, sigErr := ExtractSigningInfo(zr, r, size)
		if sigErr != nil {
			diags = append(diags, Diagnostic{
				Code:     "signing.extraction_failed",
				Severity: "warn",
				Message:  fmt.Sprintf("failed to extract signing info: %v", sigErr),
			})
		} else if sigInfo != nil {
			result.Signing = sigInfo
		}
	}

	return result, diags, nil
}

// Diagnostic is a non-fatal issue found during Android inspection.
type Diagnostic struct {
	Code     string
	Severity string
	Message  string
}

// manifest is a simplified representation of AndroidManifest.xml.
// We only parse the fields needed for mobilepkg's report model.
type manifest struct {
	XMLName         xml.Name         `xml:"manifest"`
	Package         string           `xml:"package,attr"`
	VersionCode     string           `xml:"versionCode,attr"`
	VersionName     string           `xml:"versionName,attr"`
	App             application      `xml:"application"`
	UsesPermissions []usesPermission `xml:"uses-permission"`
	UsesSdk         usesSdk          `xml:"uses-sdk"`
}

type usesSdk struct {
	MinSdkVersion    string `xml:"minSdkVersion,attr"`
	TargetSdkVersion string `xml:"targetSdkVersion,attr"`
}

type application struct {
	Label      string     `xml:"label,attr"`
	Icon       string     `xml:"icon,attr"`
	Activities []activity `xml:"activity"`
}

type activity struct {
	Name          string         `xml:"name,attr"`
	IntentFilters []intentFilter `xml:"intent-filter"`
}

type intentFilter struct {
	Actions    []action   `xml:"action"`
	Categories []category `xml:"category"`
}

type action struct {
	Name string `xml:"name,attr"`
}

type category struct {
	Name string `xml:"name,attr"`
}

type usesPermission struct {
	Name string `xml:"name,attr"`
}

func findMainActivity(m manifest) string {
	for _, act := range m.App.Activities {
		for _, intent := range act.IntentFilters {
			hasMain := false
			hasLauncher := false
			for _, a := range intent.Actions {
				if a.Name == "android.intent.action.MAIN" {
					hasMain = true
				}
			}
			for _, c := range intent.Categories {
				if c.Name == "android.intent.category.LAUNCHER" {
					hasLauncher = true
				}
			}
			if hasMain && hasLauncher {
				return act.Name
			}
		}
	}
	return ""
}

func readZipFile(zr *zip.Reader, name string) ([]byte, error) {
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer func() { _ = rc.Close() }()
		return io.ReadAll(rc)
	}
	return nil, fmt.Errorf("file %q not found in archive", name)
}

func detectImageFormat(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".png"):
		return "png"
	case strings.HasSuffix(lower, ".jpg"), strings.HasSuffix(lower, ".jpeg"):
		return "jpeg"
	case strings.HasSuffix(lower, ".webp"):
		return "webp"
	default:
		return ""
	}
}

// --- Minimal binary XML parser ---
// This is a simplified version of the androidbinary XML parser.
// It converts the binary XML format used in APK files into text XML
// that can be decoded by encoding/xml.

type resChunkHeader struct {
	Type       uint16
	HeaderSize uint16
	Size       uint32
}

type resStringPoolHeader struct {
	Header      resChunkHeader
	StringCount uint32
	StyleCount  uint32
	Flags       uint32
	StringStart uint32
	StylesStart uint32
}

type resStringPool struct {
	strings []string
}

const (
	resStringPoolChunkType uint16 = 0x0001
	resXMLStartNamespace   uint16 = 0x0100
	resXMLEndNamespace     uint16 = 0x0101
	resXMLStartElement     uint16 = 0x0102
	resXMLEndElement       uint16 = 0x0103
	nilRef                 uint32 = 0xFFFFFFFF

	utf8Flag uint32 = 1 << 8

	typeNull      uint8 = 0x00
	typeReference uint8 = 0x01
	typeString    uint8 = 0x03
	typeIntDec    uint8 = 0x10
	typeIntHex    uint8 = 0x11
	typeIntBool   uint8 = 0x12
)

type xmlFile struct {
	pool       *resStringPool
	namespaces map[uint32]uint32 // URI ref -> prefix ref
	buf        bytes.Buffer
}

func newXMLFile(r io.ReaderAt) (*xmlFile, error) {
	f := &xmlFile{
		namespaces: make(map[uint32]uint32),
	}
	sr := io.NewSectionReader(r, 0, 1<<63-1)

	f.buf.WriteString(xml.Header)

	var header resChunkHeader
	if err := binary.Read(sr, binary.LittleEndian, &header); err != nil {
		return nil, err
	}

	offset := int64(header.HeaderSize)
	for offset < int64(header.Size) {
		ch, err := f.readChunk(r, offset)
		if err != nil {
			return nil, err
		}
		offset += int64(ch.Size)
	}
	return f, nil
}

func (f *xmlFile) reader() *bytes.Reader {
	return bytes.NewReader(f.buf.Bytes())
}

func (f *xmlFile) readChunk(r io.ReaderAt, offset int64) (*resChunkHeader, error) {
	sr := io.NewSectionReader(r, offset, 1<<63-1-offset)
	var ch resChunkHeader
	if err := binary.Read(sr, binary.LittleEndian, &ch); err != nil {
		return nil, err
	}

	if _, err := sr.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	switch ch.Type {
	case resStringPoolChunkType:
		pool, err := readStringPool(sr)
		if err != nil {
			return nil, err
		}
		f.pool = pool
	case resXMLStartNamespace:
		if err := f.readStartNS(sr); err != nil {
			return nil, err
		}
	case resXMLEndNamespace:
		if err := f.readEndNS(sr); err != nil {
			return nil, err
		}
	case resXMLStartElement:
		if err := f.readStartElem(sr); err != nil {
			return nil, err
		}
	case resXMLEndElement:
		if err := f.readEndElem(sr); err != nil {
			return nil, err
		}
	}

	return &ch, nil
}

func readStringPool(sr *io.SectionReader) (*resStringPool, error) {
	var hdr resStringPoolHeader
	if err := binary.Read(sr, binary.LittleEndian, &hdr); err != nil {
		return nil, err
	}

	offsets := make([]uint32, hdr.StringCount)
	if err := binary.Read(sr, binary.LittleEndian, offsets); err != nil {
		return nil, err
	}

	// skip style offsets
	styleOffsets := make([]uint32, hdr.StyleCount)
	if err := binary.Read(sr, binary.LittleEndian, styleOffsets); err != nil {
		return nil, err
	}

	pool := &resStringPool{
		strings: make([]string, hdr.StringCount),
	}

	isUTF8 := (hdr.Flags & utf8Flag) != 0

	for i, off := range offsets {
		pos := int64(hdr.StringStart + off)
		if _, err := sr.Seek(pos, io.SeekStart); err != nil {
			return nil, err
		}
		if isUTF8 {
			s, err := readUTF8String(sr)
			if err != nil {
				return nil, err
			}
			pool.strings[i] = s
		} else {
			s, err := readUTF16String(sr)
			if err != nil {
				return nil, err
			}
			pool.strings[i] = s
		}
	}

	return pool, nil
}

func readUTF16String(r io.Reader) (string, error) {
	size, err := readUTF16Len(r)
	if err != nil {
		return "", err
	}
	buf := make([]uint16, size)
	if err := binary.Read(r, binary.LittleEndian, buf); err != nil {
		return "", err
	}
	runes := make([]rune, len(buf))
	for i, v := range buf {
		runes[i] = rune(v)
	}
	return string(runes), nil
}

func readUTF16Len(r io.Reader) (int, error) {
	var first uint16
	if err := binary.Read(r, binary.LittleEndian, &first); err != nil {
		return 0, err
	}
	if (first & 0x8000) != 0 {
		var second uint16
		if err := binary.Read(r, binary.LittleEndian, &second); err != nil {
			return 0, err
		}
		return (int(first&0x7FFF) << 16) + int(second), nil
	}
	return int(first), nil
}

func readUTF8String(r io.Reader) (string, error) {
	// skip UTF-16 length
	if _, err := readUTF8Len(r); err != nil {
		return "", err
	}
	size, err := readUTF8Len(r)
	if err != nil {
		return "", err
	}
	buf := make([]byte, size)
	if err := binary.Read(r, binary.LittleEndian, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func readUTF8Len(r io.Reader) (int, error) {
	var first uint8
	if err := binary.Read(r, binary.LittleEndian, &first); err != nil {
		return 0, err
	}
	if (first & 0x80) != 0 {
		var second uint8
		if err := binary.Read(r, binary.LittleEndian, &second); err != nil {
			return 0, err
		}
		return (int(first&0x7F) << 8) + int(second), nil
	}
	return int(first), nil
}

func (f *xmlFile) getString(ref uint32) string {
	if f.pool == nil || int(ref) >= len(f.pool.strings) {
		return ""
	}
	return f.pool.strings[ref]
}

func (f *xmlFile) hasString(ref uint32) bool {
	return f.pool != nil && int(ref) < len(f.pool.strings)
}

type resXMLTreeNode struct {
	Header     resChunkHeader
	LineNumber uint32
	Comment    uint32
}

type resXMLTreeNSExt struct {
	Prefix uint32
	URI    uint32
}

type resXMLTreeAttrExt struct {
	NS             uint32
	Name           uint32
	AttributeStart uint16
	AttributeSize  uint16
	AttributeCount uint16
	IDIndex        uint16
	ClassIndex     uint16
	StyleIndex     uint16
}

type resXMLTreeAttribute struct {
	NS         uint32
	Name       uint32
	RawValue   uint32
	TypedValue struct {
		Size     uint16
		Res0     uint8
		DataType uint8
		Data     uint32
	}
}

type resXMLTreeEndElemExt struct {
	NS   uint32
	Name uint32
}

func (f *xmlFile) addNSPrefix(ns, name uint32) string {
	if !f.hasString(name) {
		return ""
	}
	n := f.getString(name)
	if ns != nilRef {
		if prefix, ok := f.namespaces[ns]; ok && f.hasString(prefix) {
			return f.getString(prefix) + ":" + n
		}
	}
	return n
}

func (f *xmlFile) readStartNS(sr *io.SectionReader) error {
	var node resXMLTreeNode
	if err := binary.Read(sr, binary.LittleEndian, &node); err != nil {
		return err
	}
	if _, err := sr.Seek(int64(node.Header.HeaderSize), io.SeekStart); err != nil {
		return err
	}
	var ext resXMLTreeNSExt
	if err := binary.Read(sr, binary.LittleEndian, &ext); err != nil {
		return err
	}
	f.namespaces[ext.URI] = ext.Prefix
	return nil
}

func (f *xmlFile) readEndNS(sr *io.SectionReader) error {
	var node resXMLTreeNode
	if err := binary.Read(sr, binary.LittleEndian, &node); err != nil {
		return err
	}
	if _, err := sr.Seek(int64(node.Header.HeaderSize), io.SeekStart); err != nil {
		return err
	}
	var ext resXMLTreeNSExt
	if err := binary.Read(sr, binary.LittleEndian, &ext); err != nil {
		return err
	}
	delete(f.namespaces, ext.URI)
	return nil
}

func (f *xmlFile) readStartElem(sr *io.SectionReader) error {
	var node resXMLTreeNode
	if err := binary.Read(sr, binary.LittleEndian, &node); err != nil {
		return err
	}
	if _, err := sr.Seek(int64(node.Header.HeaderSize), io.SeekStart); err != nil {
		return err
	}
	var ext resXMLTreeAttrExt
	if err := binary.Read(sr, binary.LittleEndian, &ext); err != nil {
		return nil // not fatal
	}

	tag := f.addNSPrefix(ext.NS, ext.Name)
	f.buf.WriteString("<")
	f.buf.WriteString(tag)

	// write namespace declarations
	for uri, prefix := range f.namespaces {
		if f.hasString(uri) && f.hasString(prefix) {
			fmt.Fprintf(&f.buf, " xmlns:%s=\"", f.getString(prefix))
			xml.Escape(&f.buf, []byte(f.getString(uri)))
			f.buf.WriteString("\"")
		}
	}

	// write attributes
	offset := int64(ext.AttributeStart + node.Header.HeaderSize)
	for i := 0; i < int(ext.AttributeCount); i++ {
		if _, err := sr.Seek(offset, io.SeekStart); err != nil {
			return err
		}
		var attr resXMLTreeAttribute
		if err := binary.Read(sr, binary.LittleEndian, &attr); err != nil {
			return err
		}

		var value string
		if attr.RawValue != nilRef {
			value = f.getString(attr.RawValue)
		} else {
			switch attr.TypedValue.DataType {
			case typeNull:
				value = ""
			case typeReference:
				value = fmt.Sprintf("@0x%08X", attr.TypedValue.Data)
			case typeIntDec:
				value = fmt.Sprintf("%d", attr.TypedValue.Data)
			case typeIntHex:
				value = fmt.Sprintf("0x%08X", attr.TypedValue.Data)
			case typeIntBool:
				if attr.TypedValue.Data != 0 {
					value = "true"
				} else {
					value = "false"
				}
			default:
				value = fmt.Sprintf("@0x%08X", attr.TypedValue.Data)
			}
		}

		name := f.addNSPrefix(attr.NS, attr.Name)
		fmt.Fprintf(&f.buf, " %s=\"", name)
		xml.Escape(&f.buf, []byte(value))
		f.buf.WriteString("\"")
		offset += int64(ext.AttributeSize)
	}
	f.buf.WriteString(">")
	return nil
}

func (f *xmlFile) readEndElem(sr *io.SectionReader) error {
	var node resXMLTreeNode
	if err := binary.Read(sr, binary.LittleEndian, &node); err != nil {
		return err
	}
	if _, err := sr.Seek(int64(node.Header.HeaderSize), io.SeekStart); err != nil {
		return err
	}
	var ext resXMLTreeEndElemExt
	if err := binary.Read(sr, binary.LittleEndian, &ext); err != nil {
		return err
	}
	tag := f.addNSPrefix(ext.NS, ext.Name)
	fmt.Fprintf(&f.buf, "</%s>", tag)
	return nil
}

// --- Minimal resource table parser ---
// Only resolves string resources needed for label/icon resolution.

type tableFile struct {
	stringPool *resStringPool
	packages   map[uint32]*tablePackage
}

type resTableHeader struct {
	Header       resChunkHeader
	PackageCount uint32
}

type resTablePackageHeader struct {
	Header         resChunkHeader
	ID             uint32
	Name           [128]uint16
	TypeStrings    uint32
	LastPublicType uint32
	KeyStrings     uint32
	LastPublicKey  uint32
}

type tablePackage struct {
	header      resTablePackageHeader
	typeStrings *resStringPool
	keyStrings  *resStringPool
	types       []*tableType
}

type resTableTypeHeader struct {
	Header       resChunkHeader
	ID           uint8
	Res0         uint8
	Res1         uint16
	EntryCount   uint32
	EntriesStart uint32
	// config follows but we skip it
}

type tableType struct {
	header  resTableTypeHeader
	entries []tableEntry
}

type resTableEntry struct {
	Size  uint16
	Flags uint16
	Key   uint32
}

type resValue struct {
	Size     uint16
	Res0     uint8
	DataType uint8
	Data     uint32
}

type tableEntry struct {
	key   *resTableEntry
	value *resValue
}

const (
	resTableChunkType    uint16 = 0x0002
	resTablePackageType  uint16 = 0x0200
	resTableTypeType     uint16 = 0x0201
	resTableTypeSpecType uint16 = 0x0202
)

func newTableFile(r io.ReaderAt) (*tableFile, error) {
	tf := &tableFile{
		packages: make(map[uint32]*tablePackage),
	}
	sr := io.NewSectionReader(r, 0, 1<<63-1)
	var header resTableHeader
	if err := binary.Read(sr, binary.LittleEndian, &header); err != nil {
		return nil, err
	}

	offset := int64(header.Header.HeaderSize)
	for offset < int64(header.Header.Size) {
		ch, err := tf.readTableChunk(r, offset)
		if err != nil {
			return nil, err
		}
		offset += int64(ch.Size)
	}
	return tf, nil
}

func (tf *tableFile) readTableChunk(r io.ReaderAt, offset int64) (*resChunkHeader, error) {
	sr := io.NewSectionReader(r, offset, 1<<63-1-offset)
	var ch resChunkHeader
	if err := binary.Read(sr, binary.LittleEndian, &ch); err != nil {
		return nil, err
	}
	if _, err := sr.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	switch ch.Type {
	case resStringPoolChunkType:
		pool, err := readStringPool(sr)
		if err != nil {
			return nil, err
		}
		tf.stringPool = pool
	case resTablePackageType:
		pkg, err := readTablePackage(sr)
		if err != nil {
			return nil, err
		}
		tf.packages[pkg.header.ID] = pkg
	}
	return &ch, nil
}

func readTablePackage(sr *io.SectionReader) (*tablePackage, error) {
	var hdr resTablePackageHeader
	if err := binary.Read(sr, binary.LittleEndian, &hdr); err != nil {
		return nil, err
	}

	pkg := &tablePackage{header: hdr}

	// Read type strings
	tsr := io.NewSectionReader(sr, int64(hdr.TypeStrings), int64(hdr.Header.Size-hdr.TypeStrings))
	if pool, err := readStringPool(tsr); err == nil {
		pkg.typeStrings = pool
	}

	// Read key strings
	ksr := io.NewSectionReader(sr, int64(hdr.KeyStrings), int64(hdr.Header.Size-hdr.KeyStrings))
	if pool, err := readStringPool(ksr); err == nil {
		pkg.keyStrings = pool
	}

	offset := int64(hdr.Header.HeaderSize)
	for offset < int64(hdr.Header.Size) {
		if _, err := sr.Seek(offset, io.SeekStart); err != nil {
			return nil, err
		}
		var ch resChunkHeader
		if err := binary.Read(sr, binary.LittleEndian, &ch); err != nil {
			return nil, err
		}

		if ch.Type == resTableTypeType {
			tt, err := readTableType(sr, offset, ch)
			if err == nil {
				pkg.types = append(pkg.types, tt)
			}
		}
		offset += int64(ch.Size)
	}

	return pkg, nil
}

func readTableType(sr *io.SectionReader, baseOffset int64, ch resChunkHeader) (*tableType, error) {
	if _, err := sr.Seek(baseOffset, io.SeekStart); err != nil {
		return nil, err
	}
	var hdr resTableTypeHeader
	if err := binary.Read(sr, binary.LittleEndian, &hdr); err != nil {
		return nil, err
	}

	// Skip the config bytes that follow the header
	if _, err := sr.Seek(baseOffset+int64(ch.HeaderSize), io.SeekStart); err != nil {
		return nil, err
	}

	// Read entry index array
	// The area between headerSize and entriesStart contains the entry offsets
	indexCount := hdr.EntryCount
	indexes := make([]uint32, indexCount)
	if err := binary.Read(sr, binary.LittleEndian, indexes); err != nil {
		return nil, err
	}

	entries := make([]tableEntry, indexCount)
	for i, idx := range indexes {
		if idx == 0xFFFFFFFF {
			continue
		}
		entryOffset := baseOffset + int64(hdr.EntriesStart) + int64(idx)
		if _, err := sr.Seek(entryOffset, io.SeekStart); err != nil {
			return nil, err
		}
		var key resTableEntry
		if err := binary.Read(sr, binary.LittleEndian, &key); err != nil {
			continue
		}
		var val resValue
		if err := binary.Read(sr, binary.LittleEndian, &val); err != nil {
			continue
		}
		entries[i] = tableEntry{key: &key, value: &val}
	}

	return &tableType{header: hdr, entries: entries}, nil
}

func (tf *tableFile) getResource(id uint32) (string, bool) {
	pkgID := id >> 24
	typeID := int((id >> 16) & 0xFF)
	entryID := int(id & 0xFFFF)

	pkg, ok := tf.packages[pkgID]
	if !ok {
		return "", false
	}

	for _, tt := range pkg.types {
		if int(tt.header.ID) != typeID {
			continue
		}
		if entryID >= len(tt.entries) {
			continue
		}
		e := tt.entries[entryID]
		if e.value == nil {
			continue
		}
		if e.value.DataType == typeString {
			if tf.stringPool != nil && int(e.value.Data) < len(tf.stringPool.strings) {
				return tf.stringPool.strings[e.value.Data], true
			}
		}
	}
	return "", false
}

func resolveString(s string, table *tableFile) string {
	if !strings.HasPrefix(s, "@0x") {
		return s
	}
	if table == nil {
		return s
	}
	var id uint64
	_, err := fmt.Sscanf(s, "@0x%X", &id)
	if err != nil {
		return s
	}
	if resolved, ok := table.getResource(uint32(id)); ok {
		return resolved
	}
	return s
}

func injectTable(m *manifest, table *tableFile) {
	m.App.Label = resolveString(m.App.Label, table)
	m.App.Icon = resolveString(m.App.Icon, table)
}
