package android

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"strings"
)

// NetworkSecurityPolicy holds the parsed content of an Android
// network_security_config.xml file.
type NetworkSecurityPolicy struct {
	CleartextPermitted bool           `json:"cleartext_permitted"`
	DomainConfigs      []DomainConfig `json:"domain_configs,omitempty"`
	TrustAnchors       []string       `json:"trust_anchors,omitempty"`
	HasPinSet          bool           `json:"has_pin_set"`
	HasDebugOverrides  bool           `json:"has_debug_overrides"`
}

// DomainConfig represents a <domain-config> entry in network_security_config.xml.
type DomainConfig struct {
	Domains            []string       `json:"domains"`
	CleartextPermitted bool           `json:"cleartext_permitted"`
	HasPinSet          bool           `json:"has_pin_set"`
	NestedConfigs      []DomainConfig `json:"nested_configs,omitempty"`
}

// nscRoot is the XML root element of network_security_config.xml.
type nscRoot struct {
	XMLName        xml.Name           `xml:"network-security-config"`
	BaseConfig     *nscBaseConfig     `xml:"base-config"`
	DomainConfigs  []nscDomainConfig  `xml:"domain-config"`
	DebugOverrides *nscDebugOverrides `xml:"debug-overrides"`
}

type nscBaseConfig struct {
	CleartextTraffic string           `xml:"cleartextTrafficPermitted,attr"`
	TrustAnchors     *nscTrustAnchors `xml:"trust-anchors"`
}

type nscDebugOverrides struct {
	TrustAnchors *nscTrustAnchors `xml:"trust-anchors"`
}

type nscDomainConfig struct {
	CleartextTraffic string            `xml:"cleartextTrafficPermitted,attr"`
	Domains          []nscDomain       `xml:"domain"`
	PinSet           *nscPinSet        `xml:"pin-set"`
	TrustAnchors     *nscTrustAnchors  `xml:"trust-anchors"`
	NestedConfigs    []nscDomainConfig `xml:"domain-config"`
}

type nscDomain struct {
	IncludeSubdomains string `xml:"includeSubdomains,attr"`
	Value             string `xml:",chardata"`
}

type nscPinSet struct {
	Expiration string   `xml:"expiration,attr"`
	Pins       []nscPin `xml:"pin"`
}

type nscPin struct {
	Digest string `xml:"digest,attr"`
	Value  string `xml:",chardata"`
}

type nscTrustAnchors struct {
	Certificates []nscCertificate `xml:"certificates"`
}

type nscCertificate struct {
	Src string `xml:"src,attr"`
}

// parseNetworkSecurityConfig reads and parses network_security_config.xml
// from the ZIP archive. The configRef is the manifest attribute value,
// which may be a resource reference like "@xml/network_security_config".
func parseNetworkSecurityConfig(zr *zip.Reader, configRef string, maxBytes int64) *NetworkSecurityPolicy {
	if configRef == "" {
		return nil
	}

	// Resolve the path. Common forms:
	// - "@xml/network_security_config" → "res/xml/network_security_config.xml"
	// - "res/xml/network_security_config.xml" → as-is
	path := resolveNSCPath(configRef)
	if path == "" {
		// Fallback: scan ZIP for the file by name pattern.
		path = scanForNSCFile(zr)
		if path == "" {
			return nil
		}
	}

	data, err := readZipFile(zr, path, maxBytes)
	if err != nil {
		return nil
	}

	// NSC files in APKs are binary XML. Try to convert first.
	xmlData := tryDecodeBinaryXML(data)

	var root nscRoot
	if err := xml.Unmarshal(xmlData, &root); err != nil {
		return nil
	}

	policy := &NetworkSecurityPolicy{}

	// Base config.
	if root.BaseConfig != nil {
		policy.CleartextPermitted = strings.EqualFold(root.BaseConfig.CleartextTraffic, "true")
		if root.BaseConfig.TrustAnchors != nil {
			for _, cert := range root.BaseConfig.TrustAnchors.Certificates {
				policy.TrustAnchors = append(policy.TrustAnchors, cert.Src)
			}
		}
	}

	// Domain configs (with recursive nested support).
	for _, dc := range root.DomainConfigs {
		domainCfg := convertDomainConfig(dc, policy)
		policy.DomainConfigs = append(policy.DomainConfigs, domainCfg)
	}

	// Debug overrides.
	if root.DebugOverrides != nil {
		policy.HasDebugOverrides = true
		if root.DebugOverrides.TrustAnchors != nil {
			for _, cert := range root.DebugOverrides.TrustAnchors.Certificates {
				policy.TrustAnchors = append(policy.TrustAnchors, "debug-overrides:"+cert.Src)
			}
		}
	}

	return policy
}

// convertDomainConfig recursively converts an nscDomainConfig (XML) into a
// DomainConfig, including any nested domain-config elements. It also updates
// the policy's HasPinSet flag as a side effect.
func convertDomainConfig(dc nscDomainConfig, policy *NetworkSecurityPolicy) DomainConfig {
	domainCfg := DomainConfig{
		CleartextPermitted: strings.EqualFold(dc.CleartextTraffic, "true"),
		HasPinSet:          dc.PinSet != nil && len(dc.PinSet.Pins) > 0,
	}
	for _, d := range dc.Domains {
		domainCfg.Domains = append(domainCfg.Domains, strings.TrimSpace(d.Value))
	}
	if domainCfg.HasPinSet {
		policy.HasPinSet = true
	}
	for _, nested := range dc.NestedConfigs {
		domainCfg.NestedConfigs = append(domainCfg.NestedConfigs, convertDomainConfig(nested, policy))
	}
	return domainCfg
}

// resolveNSCPath resolves the networkSecurityConfig attribute value to a
// ZIP entry path. It handles:
//   - "@xml/name" → "res/xml/name.xml"
//   - "@0x7F..." → "" (resource ID; needs fallback scan)
//   - "res/xml/name.xml" → as-is
func resolveNSCPath(ref string) string {
	if strings.HasPrefix(ref, "@0x") {
		// Binary resource ID — cannot resolve directly.
		return ""
	}
	if strings.HasPrefix(ref, "@") {
		ref = strings.TrimPrefix(ref, "@")
		return "res/" + ref + ".xml"
	}
	if strings.Contains(ref, "/") {
		return ref
	}
	return ""
}

// scanForNSCFile searches the ZIP for a network_security_config.xml file.
// It first tries the common name pattern, then falls back to probing
// small XML files in res/ for the network-security-config root element.
// This handles both normal and resource-minified (R8/ProGuard) APKs.
func scanForNSCFile(zr *zip.Reader) string {
	// Fast path: match by name.
	for _, f := range zr.File {
		if strings.Contains(f.Name, "network_security_config") &&
			strings.HasSuffix(f.Name, ".xml") &&
			strings.HasPrefix(f.Name, "res/") {
			return f.Name
		}
	}

	// Slow path: probe small XML files in res/ for the correct root element.
	// Only check files < 10KB to limit cost (NSC files are typically < 2KB).
	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, "res/") || !strings.HasSuffix(f.Name, ".xml") {
			continue
		}
		if f.UncompressedSize64 > 10240 {
			continue
		}
		data, err := readZipFile(zr, f.Name, 10240)
		if err != nil {
			continue
		}
		decoded := tryDecodeBinaryXML(data)
		if bytes.Contains(decoded, []byte("network-security-config")) {
			return f.Name
		}
	}

	return ""
}

// tryDecodeBinaryXML attempts to decode binary Android XML into text XML.
// If the input is not binary XML or decoding fails, it returns the input as-is.
func tryDecodeBinaryXML(data []byte) []byte {
	// Binary XML starts with ResXMLTree type 0x0003.
	if len(data) < 4 || data[0] != 0x03 || data[1] != 0x00 {
		return data // Not binary XML, return as-is (may be plain text XML).
	}
	xf, err := newXMLFile(bytes.NewReader(data))
	if err != nil {
		return data
	}
	return xf.buf.Bytes()
}
