// Command genapk writes the Android packages the himorime suite in bench/
// inspects. It copies every entry of a real APK (the committed AndroGoat
// fixture: binary manifest, v1 signature, resources) and adds a classes.dex
// whose string table holds N strings: class descriptors, messages, and one in
// a hundred an http:// URL, one in a hundred an https:// URL, so the DEX
// scanners have findings to report. -shift moves the numbering, so two
// packages written with different shifts hold different DEX strings.
// The output is the same for the same arguments. It is run through
// bench/gen.sh.
package main

import (
	"archive/zip"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "genapk:", err)
		os.Exit(1)
	}
}

func run() error {
	from := flag.String("from", "", "APK whose entries are copied")
	n := flag.Int("strings", 10, "strings in the DEX string table")
	shift := flag.Int("shift", 0, "first number used in the strings")
	out := flag.String("out", "", "APK to write")
	flag.Parse()
	if *from == "" || *out == "" || *n < 1 {
		return errors.New("usage: genapk -from APK -strings N [-shift K] -out APK")
	}

	src, err := zip.OpenReader(*from)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()

	if err := os.MkdirAll(filepath.Dir(*out), 0o750); err != nil {
		return err
	}
	f, err := os.Create(*out)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(f)
	for _, e := range src.File {
		if e.Name == "classes.dex" {
			continue
		}
		if err := zw.Copy(e); err != nil {
			_ = f.Close()
			return err
		}
	}
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "classes.dex", Method: zip.Deflate})
	if err != nil {
		_ = f.Close()
		return err
	}
	if _, err := w.Write(buildDEX(dexStrings(*n, *shift))); err != nil {
		_ = f.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// dexStrings returns n strings of the kinds an app's string table holds.
func dexStrings(n, shift int) []string {
	strs := make([]string, 0, n)
	for i := shift; i < shift+n; i++ {
		var s string
		switch {
		case i%100 == 0:
			s = fmt.Sprintf("http://api%d.example.com/v1/items", i)
		case i%100 == 50:
			s = fmt.Sprintf("https://cdn%d.example.com/assets/app.js", i)
		case i%2 == 0:
			s = fmt.Sprintf("Lcom/example/app/feature%d/Screen%d;", i/100, i)
		default:
			s = fmt.Sprintf("message number %d shown to the user", i)
		}
		strs = append(strs, s)
	}
	return strs
}

// buildDEX returns a DEX file whose only section is the string table.
func buildDEX(strs []string) []byte {
	const headerSize = 0x70
	le := binary.LittleEndian

	ids := make([]byte, len(strs)*4)
	dataOff := headerSize + len(ids)
	var data []byte
	for i, s := range strs {
		le.PutUint32(ids[i*4:], uint32(dataOff+len(data))) //nolint:gosec // bounded by the size of a generated file
		data = appendULEB128(data, uint32(len(s)))         //nolint:gosec // ASCII strings of a few dozen bytes
		data = append(data, s...)
		data = append(data, 0)
	}

	hdr := make([]byte, headerSize, headerSize+len(ids)+len(data))
	copy(hdr[0:8], "dex\n035\x00")
	le.PutUint32(hdr[32:36], uint32(dataOff+len(data))) //nolint:gosec // bounded by the size of a generated file
	le.PutUint32(hdr[36:40], headerSize)
	le.PutUint32(hdr[40:44], 0x12345678)
	le.PutUint32(hdr[56:60], uint32(len(strs))) //nolint:gosec // bounded by -strings
	le.PutUint32(hdr[60:64], headerSize)
	le.PutUint32(hdr[104:108], uint32(len(data))) //nolint:gosec // bounded by the size of a generated file
	le.PutUint32(hdr[108:112], uint32(dataOff))   //nolint:gosec // bounded by the size of a generated file

	return append(append(hdr, ids...), data...)
}

func appendULEB128(buf []byte, v uint32) []byte {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if v == 0 {
			return buf
		}
	}
}
