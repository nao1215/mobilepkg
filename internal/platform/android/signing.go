package android

import (
	"archive/zip"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// SigningResult holds the signing information extracted from an APK.
type SigningResult struct {
	Scheme string
	Certs  []CertResult
}

// CertResult holds a parsed X.509 certificate summary.
type CertResult struct {
	Subject           string
	Issuer            string
	NotBefore         string // RFC 3339
	NotAfter          string // RFC 3339
	SHA256Fingerprint string // hex
	SerialNumber      string
}

// ExtractSigningInfo attempts to extract signing information from an APK.
// It tries V1 (JAR signing) from the zip.Reader and V2/V3 from the
// io.ReaderAt (APK Signing Block). Returns nil if no signing is detected.
func ExtractSigningInfo(zr *zip.Reader, r io.ReaderAt, size int64) (*SigningResult, error) {
	v1Certs, v1Err := extractV1Certs(zr)
	v2Scheme, v2Certs, v2Err := extractV2V3Certs(r, size)

	var allCerts []CertResult
	var schemes []string

	if v1Err == nil && len(v1Certs) > 0 {
		schemes = append(schemes, "v1")
		allCerts = append(allCerts, v1Certs...)
	}
	if v2Err == nil && len(v2Certs) > 0 {
		schemes = append(schemes, v2Scheme)
		// Deduplicate: only add V2/V3 certs that aren't already from V1.
		seen := make(map[string]bool)
		for _, c := range allCerts {
			seen[c.SHA256Fingerprint] = true
		}
		for _, c := range v2Certs {
			if !seen[c.SHA256Fingerprint] {
				allCerts = append(allCerts, c)
			}
		}
	}

	if len(schemes) == 0 {
		return nil, nil
	}

	return &SigningResult{
		Scheme: strings.Join(schemes, "+"),
		Certs:  allCerts,
	}, nil
}

// extractV1Certs extracts certificates from JAR signing files
// (META-INF/*.RSA or META-INF/*.DSA).
func extractV1Certs(zr *zip.Reader) ([]CertResult, error) {
	var certs []CertResult
	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, "META-INF/") {
			continue
		}
		upper := strings.ToUpper(f.Name)
		if !strings.HasSuffix(upper, ".RSA") && !strings.HasSuffix(upper, ".DSA") {
			continue
		}

		data, err := readZipFile(zr, f.Name)
		if err != nil {
			continue
		}

		parsed, err := parsePKCS7Certs(data)
		if err != nil {
			continue
		}
		certs = append(certs, parsed...)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no V1 signing certificates found")
	}
	return certs, nil
}

// parsePKCS7Certs extracts X.509 certificates from a PKCS#7 SignedData blob.
// The structure is:
//
//	ContentInfo ::= SEQUENCE {
//	  contentType OID,
//	  content [0] EXPLICIT SignedData
//	}
//	SignedData ::= SEQUENCE {
//	  version INTEGER,
//	  digestAlgorithms SET,
//	  contentInfo SEQUENCE,
//	  certificates [0] IMPLICIT SET OF Certificate, -- what we want
//	  ...
//	}
func parsePKCS7Certs(data []byte) ([]CertResult, error) {
	// Parse ContentInfo
	var contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(data, &contentInfo); err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#7 ContentInfo: %w", err)
	}

	// Parse SignedData (inside Content)
	var signedData struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      asn1.RawValue
		Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	}
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signedData); err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#7 SignedData: %w", err)
	}

	// The certificates field is a SET OF Certificate (implicit tag 0).
	// We need to parse individual certificate DER blobs from it.
	if len(signedData.Certificates.Bytes) == 0 {
		return nil, fmt.Errorf("no certificates in PKCS#7 SignedData")
	}

	return parseCertificatesFromDER(signedData.Certificates.Bytes)
}

// parseCertificatesFromDER parses a sequence of DER-encoded X.509 certificates.
// Each certificate is first isolated via asn1.Unmarshal (which correctly handles
// trailing data), then parsed with x509.ParseCertificate on the exact FullBytes.
func parseCertificatesFromDER(data []byte) ([]CertResult, error) {
	var results []CertResult
	rest := data
	for len(rest) > 0 {
		var raw asn1.RawValue
		remainder, err := asn1.Unmarshal(rest, &raw)
		if err != nil {
			break
		}
		cert, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			// Skip malformed entries.
			rest = remainder
			continue
		}
		results = append(results, certToSummary(cert))
		rest = remainder
	}
	return results, nil
}

// certToSummary converts an x509.Certificate to a CertResult.
func certToSummary(cert *x509.Certificate) CertResult {
	subject := cert.Subject.CommonName
	if subject == "" && len(cert.Subject.Organization) > 0 {
		subject = cert.Subject.Organization[0]
	}
	if subject == "" {
		subject = cert.Subject.String()
	}

	issuer := cert.Issuer.CommonName
	if issuer == "" && len(cert.Issuer.Organization) > 0 {
		issuer = cert.Issuer.Organization[0]
	}
	if issuer == "" {
		issuer = cert.Issuer.String()
	}

	fp := sha256.Sum256(cert.Raw)

	return CertResult{
		Subject:           subject,
		Issuer:            issuer,
		NotBefore:         cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		NotAfter:          cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		SHA256Fingerprint: fmt.Sprintf("%x", fp),
		SerialNumber:      cert.SerialNumber.String(),
	}
}

// APK Signing Block constants.
const (
	apkSigBlockMagic = "APK Sig Block 42"
	apkSigV2BlockID  = 0x7109871a
	apkSigV3BlockID  = 0xf05368c0
)

// extractV2V3Certs looks for the APK Signing Block and extracts certificates
// from V2 or V3 signer blocks.
func extractV2V3Certs(r io.ReaderAt, size int64) (scheme string, certs []CertResult, err error) {
	block, err := findAPKSigningBlock(r, size)
	if err != nil {
		return "", nil, err
	}

	// Try V3 first (higher priority), then V2.
	for _, try := range []struct {
		id     uint32
		scheme string
	}{
		{apkSigV3BlockID, "v3"},
		{apkSigV2BlockID, "v2"},
	} {
		signerData, findErr := findBlockByID(block, try.id)
		if findErr != nil || len(signerData) == 0 {
			continue
		}

		parsed, parseErr := parseSignersCerts(signerData)
		if parseErr != nil || len(parsed) == 0 {
			continue
		}

		return try.scheme, parsed, nil
	}

	return "", nil, fmt.Errorf("no V2/V3 signing block found")
}

// findAPKSigningBlock locates the APK Signing Block by searching backwards
// from the Central Directory.
//
// APK layout: [ZIP entries] [APK Signing Block] [Central Directory] [EOCD]
//
// We find EOCD → get CD offset → the signing block is right before CD.
func findAPKSigningBlock(r io.ReaderAt, size int64) ([]byte, error) {
	// Find End of Central Directory record.
	// EOCD is at most 65535+22 bytes from the end.
	eocdSearchSize := int64(65536 + 22)
	if eocdSearchSize > size {
		eocdSearchSize = size
	}

	buf := make([]byte, eocdSearchSize)
	if _, err := r.ReadAt(buf, size-eocdSearchSize); err != nil {
		return nil, fmt.Errorf("failed to read EOCD region: %w", err)
	}

	// Search for EOCD signature (0x06054b50) from the end.
	eocdSig := []byte{0x50, 0x4b, 0x05, 0x06}
	eocdPos := -1
	for i := len(buf) - 22; i >= 0; i-- {
		if buf[i] == eocdSig[0] && buf[i+1] == eocdSig[1] &&
			buf[i+2] == eocdSig[2] && buf[i+3] == eocdSig[3] {
			eocdPos = i
			break
		}
	}
	if eocdPos < 0 {
		return nil, fmt.Errorf("EOCD not found")
	}

	// Central Directory offset is at EOCD+16 (4 bytes, little-endian).
	cdOffset := binary.LittleEndian.Uint32(buf[eocdPos+16 : eocdPos+20])

	// The APK Signing Block ends right before the Central Directory.
	// Its footer is: [size_of_block (8 bytes)] [magic (16 bytes)]
	// Total footer: 24 bytes.
	if int64(cdOffset) < 24 {
		return nil, fmt.Errorf("not enough space for APK Signing Block")
	}

	// Read the footer (last 24 bytes before CD).
	footer := make([]byte, 24)
	if _, err := r.ReadAt(footer, int64(cdOffset)-24); err != nil {
		return nil, fmt.Errorf("failed to read signing block footer: %w", err)
	}

	// Check magic.
	magic := string(footer[8:24])
	if magic != apkSigBlockMagic {
		return nil, fmt.Errorf("APK Signing Block magic not found")
	}

	// Size of block (from footer) — this is the size excluding the 8-byte
	// size field at the very beginning of the block.
	blockSize := binary.LittleEndian.Uint64(footer[0:8])
	blockStart := int64(cdOffset) - 8 - int64(blockSize)
	if blockStart < 0 {
		return nil, fmt.Errorf("invalid APK Signing Block size")
	}

	// Read the entire block.
	// The block starts with: [size_of_block (8)] [id-value pairs...] [size_of_block (8)] [magic (16)]
	totalSize := int64(cdOffset) - blockStart
	block := make([]byte, totalSize)
	if _, err := r.ReadAt(block, blockStart); err != nil {
		return nil, fmt.Errorf("failed to read APK Signing Block: %w", err)
	}

	return block, nil
}

// findBlockByID searches the APK Signing Block for an id-value pair with the
// given ID and returns the value bytes.
//
// Block layout after the initial 8-byte size:
//
//	[pair_size (8)] [id (4)] [value (pair_size-4 bytes)] ...
//
// Followed by [size_of_block (8)] [magic (16)].
func findBlockByID(block []byte, id uint32) ([]byte, error) {
	if len(block) < 32 {
		return nil, fmt.Errorf("block too small")
	}

	// Skip the first 8-byte size field.
	pos := 8
	// Pairs end 24 bytes before the end (footer: 8-byte size + 16-byte magic).
	end := len(block) - 24

	for pos < end {
		if pos+8 > end {
			break
		}
		pairSize := binary.LittleEndian.Uint64(block[pos : pos+8])
		pos += 8
		if pairSize < 4 || int(pairSize) > end-pos {
			break
		}
		pairID := binary.LittleEndian.Uint32(block[pos : pos+4])
		if pairID == id {
			return block[pos+4 : pos+int(pairSize)], nil
		}
		pos += int(pairSize)
	}

	return nil, fmt.Errorf("block ID 0x%08x not found", id)
}

// parseSignersCerts extracts X.509 certificates from V2/V3 signer blocks.
//
// The signer block value contains a length-prefixed sequence of signers:
//
//	signers_length (4) [signer_length (4) signer_data ...]
//
// Each signer contains:
//
//	signed_data_length (4) signed_data
//	signatures_length (4) signatures
//	public_key_length (4) public_key
//
// signed_data contains:
//
//	digests_length (4) digests
//	certificates_length (4) [cert_length (4) cert_der ...] ← what we want
//	...
func parseSignersCerts(data []byte) ([]CertResult, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("signer block too short")
	}

	var results []CertResult

	// signers sequence
	signersLen := int(binary.LittleEndian.Uint32(data[0:4]))
	pos := 4
	signersEnd := pos + signersLen
	if signersEnd > len(data) {
		signersEnd = len(data)
	}

	for pos < signersEnd {
		if pos+4 > signersEnd {
			break
		}
		signerLen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
		pos += 4
		signerEnd := pos + signerLen
		if signerEnd > signersEnd {
			break
		}

		certs, _ := parseSignerCerts(data[pos:signerEnd])
		results = append(results, certs...)
		pos = signerEnd
	}

	return results, nil
}

// parseSignerCerts extracts certificates from a single signer block.
func parseSignerCerts(data []byte) ([]CertResult, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("signer data too short")
	}

	// signed_data_length (4) + signed_data
	signedDataLen := int(binary.LittleEndian.Uint32(data[0:4]))
	if signedDataLen+4 > len(data) {
		return nil, fmt.Errorf("signed data length exceeds signer")
	}
	signedData := data[4 : 4+signedDataLen]

	// Inside signed_data: digests_length (4) + digests, then certificates_length (4) + certificates
	if len(signedData) < 4 {
		return nil, fmt.Errorf("signed data too short for digests")
	}
	digestsLen := int(binary.LittleEndian.Uint32(signedData[0:4]))
	certsOffset := 4 + digestsLen
	if certsOffset+4 > len(signedData) {
		return nil, fmt.Errorf("signed data too short for certificates")
	}

	certsLen := int(binary.LittleEndian.Uint32(signedData[certsOffset : certsOffset+4]))
	certsData := signedData[certsOffset+4:]
	if certsLen > len(certsData) {
		certsLen = len(certsData)
	}

	var results []CertResult
	cPos := 0
	for cPos < certsLen {
		if cPos+4 > certsLen {
			break
		}
		certLen := int(binary.LittleEndian.Uint32(certsData[cPos : cPos+4]))
		cPos += 4
		if cPos+certLen > certsLen {
			break
		}
		cert, err := x509.ParseCertificate(certsData[cPos : cPos+certLen])
		if err == nil {
			results = append(results, certToSummary(cert))
		}
		cPos += certLen
	}

	return results, nil
}
