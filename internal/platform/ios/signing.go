package ios

import (
	"bytes"
	"crypto/dsa" //nolint:staticcheck // type assertion only; not generating DSA keys
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"time"

	"howett.net/plist"
)

// ProvisionInfo holds signing information from an iOS provisioning profile.
type ProvisionInfo struct {
	TeamID      string
	TeamName    string
	CreatedAt   string // RFC 3339
	ExpiresAt   string // RFC 3339
	Certs       []CertResult
	AppIDName   string
	ProfileName string
}

// CertResult holds a parsed X.509 certificate summary.
type CertResult struct {
	Subject            string
	Issuer             string
	NotBefore          string // RFC 3339
	NotAfter           string // RFC 3339
	SHA256Fingerprint  string // hex
	SerialNumber       string
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	KeySize            int
	SelfSigned         bool
}

// ExtractProvisioningInfo parses an embedded.mobileprovision file and
// extracts signing/certificate information.
func ExtractProvisioningInfo(data []byte) (*ProvisionInfo, error) {
	// The provisioning profile is a CMS (PKCS#7) signed plist.
	// Extract the XML plist from within the CMS blob.
	start := bytes.Index(data, []byte("<?xml"))
	if start < 0 {
		return nil, fmt.Errorf("no XML plist found in provisioning profile")
	}
	end := bytes.Index(data[start:], []byte("</plist>"))
	if end < 0 {
		return nil, fmt.Errorf("unterminated plist in provisioning profile")
	}
	end += start + len("</plist>")

	var provision map[string]any
	if _, err := plist.Unmarshal(data[start:end], &provision); err != nil {
		return nil, fmt.Errorf("failed to parse provisioning plist: %w", err)
	}

	info := &ProvisionInfo{}

	// Team identifiers
	if teams, ok := provision["TeamIdentifier"].([]any); ok && len(teams) > 0 {
		if s, ok := teams[0].(string); ok {
			info.TeamID = s
		}
	}
	if s, ok := provision["TeamName"].(string); ok {
		info.TeamName = s
	}
	if s, ok := provision["AppIDName"].(string); ok {
		info.AppIDName = s
	}
	if s, ok := provision["Name"].(string); ok {
		info.ProfileName = s
	}

	// Dates
	if t, ok := provision["CreationDate"].(time.Time); ok {
		info.CreatedAt = t.UTC().Format("2006-01-02T15:04:05Z")
	}
	if t, ok := provision["ExpirationDate"].(time.Time); ok {
		info.ExpiresAt = t.UTC().Format("2006-01-02T15:04:05Z")
	}

	// Developer certificates (DER-encoded X.509)
	if certsRaw, ok := provision["DeveloperCertificates"].([]any); ok {
		for _, raw := range certsRaw {
			certData, ok := raw.([]byte)
			if !ok {
				continue
			}
			cert, err := x509.ParseCertificate(certData)
			if err != nil {
				continue
			}
			info.Certs = append(info.Certs, certToResult(cert))
		}
	}

	return info, nil
}

func certToResult(cert *x509.Certificate) CertResult {
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

	var pubKeyAlgo string
	var keySize int
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		pubKeyAlgo = "RSA"
		if pk, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			keySize = pk.N.BitLen()
		}
	case x509.ECDSA:
		pubKeyAlgo = "ECDSA"
		if pk, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			keySize = pk.Curve.Params().BitSize
		}
	case x509.Ed25519:
		pubKeyAlgo = "Ed25519"
		keySize = 256
	case x509.DSA:
		pubKeyAlgo = "DSA"
		if pk, ok := cert.PublicKey.(*dsa.PublicKey); ok && pk.P != nil {
			keySize = pk.P.BitLen()
		}
	default:
		pubKeyAlgo = cert.PublicKeyAlgorithm.String()
	}

	return CertResult{
		Subject:            subject,
		Issuer:             issuer,
		NotBefore:          cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		NotAfter:           cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		SHA256Fingerprint:  fmt.Sprintf("%x", fp),
		SerialNumber:       cert.SerialNumber.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: pubKeyAlgo,
		KeySize:            keySize,
		SelfSigned:         cert.Subject.String() == cert.Issuer.String(),
	}
}
