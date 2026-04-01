package scanner

import (
	"fmt"
	"net/url"
	"strings"
)

type cleartextTrafficRule struct{}

func (r *cleartextTrafficRule) Name() string { return "CleartextTraffic" }

// localhostHosts are hosts that are safe for cleartext traffic.
var localhostHosts = map[string]struct{}{
	"localhost": {},
	"127.0.0.1": {},
	"10.0.2.2":  {},
	"0.0.0.0":   {},
	"[::1]":     {},
	"10.0.3.2":  {},
}

// cleartextExclusions filters out known non-URL strings that start with "http://".
// These are XML namespace URIs, specification references, example domains,
// and documentation URLs that are not actual cleartext traffic destinations.
var cleartextExclusions = []string{
	// XML/schema namespaces
	"http://schemas.android.com",
	"http://www.w3.org",
	"http://ns.adobe.com",
	"http://xmlpull.org",
	"http://java.sun.com",
	"http://xml.org",
	"http://www.xml.org",
	"http://apache.org",
	"http://www.apache.org",
	"http://purl.org",
	"http://json-schema.org",
	"http://www.json.org",
	"http://docs.oasis-open.org",
	"http://relaxng.org",
	"http://schemas.microsoft.com",
	"http://schemas.xmlsoap.org",
	"http://www.ietf.org",
	"http://tools.ietf.org",
	"http://www.iso.org",
	// Example/test domains (RFC 2606 / RFC 6761)
	"http://example.com",
	"http://example.org",
	"http://example.net",
	"http://www.example.com",
	"http://www.example.org",
	"http://www.example.net",
	// Specification and documentation URLs
	"http://dashif.org",
	"http://www.dashif.org",
	"http://id3.org",
	"http://www.id3.org",
	"http://www.unicode.org",
	"http://www.rfc-editor.org",
	"http://semver.org",
	"http://opensource.org",
	"http://creativecommons.org",
	"http://developer.android.com",
	"http://developer.apple.com",
	// Logging/library documentation
	"http://logback.qos.ch",
	"http://logging.apache.org",
	"http://slf4j.org",
	"http://www.slf4j.org",
}

func (r *cleartextTrafficRule) Match(ctx *Context) []Finding {
	var findings []Finding
	seen := make(map[string]struct{})

	for i, df := range ctx.DexFiles {
		for _, s := range df.Strings() {
			if !strings.HasPrefix(s, "http://") {
				continue
			}
			if len(s) > 1024 {
				continue
			}
			if isCleartextExcluded(s) {
				continue
			}

			u, err := url.Parse(s)
			if err != nil {
				continue
			}
			host := u.Hostname()
			if host == "" {
				continue
			}
			if _, ok := localhostHosts[host]; ok {
				continue
			}
			// Skip hostnames that are not plausible domain names — they need
			// at least two labels (e.g. "example.com"), not just "www." or
			// a bare word without dots.
			if !isPlausibleHostname(host) {
				continue
			}

			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}

			findings = append(findings, Finding{
				ID:          fmt.Sprintf("dex.cleartext.%s", sanitizeID(host)),
				Category:    "dex_cleartext",
				Severity:    "warn",
				Confidence:  "medium",
				Message:     fmt.Sprintf("cleartext HTTP URL found in DEX strings: %s", host),
				ArchivePath: ctx.dexName(i),
				Field:       "string_table",
				Matched:     truncate(s, 120),
			})
		}
	}
	return findings
}

// implausibleHosts are hostnames that appear in DEX string tables but are
// clearly not network destinations (status messages, error labels, etc.).
var implausibleHosts = map[string]struct{}{
	"wifi-not-enabled": {},
}

// isPlausibleHostname returns true if the host could be a real network
// destination. It filters out:
//   - empty hostnames
//   - trailing-dot fragments like "www." (incomplete domain)
//   - known false-positive hostnames (e.g. "wifi-not-enabled")
//   - bare TLDs (e.g. "com", "org", "net") that appear as partial hostnames
//   - "www.<TLD>" without a real domain (e.g. "www.com")
//
// Single-label hostnames (e.g. "intranet", "metadata", "api") are kept
// because they can be valid internal endpoints in mobile environments.
func isPlausibleHostname(host string) bool {
	if host == "" {
		return false
	}
	// Trailing dot means an incomplete hostname fragment (e.g. "www.").
	if strings.HasSuffix(host, ".") {
		return false
	}
	if _, ok := implausibleHosts[host]; ok {
		return false
	}
	// Bare TLDs or "www.<TLD>" are not real destinations.
	if isBareTLD(host) {
		return false
	}
	lower := strings.ToLower(host)
	if strings.HasPrefix(lower, "www.") {
		if isBareTLD(strings.TrimPrefix(lower, "www.")) {
			return false
		}
	}
	return true
}

// commonTLDs is a set of common top-level domains used to filter out
// bare TLD hostnames that appear in string tables.
var commonTLDs = map[string]struct{}{
	"com": {}, "org": {}, "net": {}, "io": {},
	"edu": {}, "gov": {}, "mil": {}, "int": {},
	"co": {}, "us": {}, "uk": {}, "de": {}, "fr": {},
	"jp": {}, "cn": {}, "ru": {}, "br": {}, "in": {},
	"au": {}, "ca": {}, "kr": {}, "it": {}, "es": {},
}

// isBareTLD returns true if the host is a bare top-level domain.
func isBareTLD(host string) bool {
	_, ok := commonTLDs[strings.ToLower(host)]
	return ok
}

func isCleartextExcluded(s string) bool {
	for _, exc := range cleartextExclusions {
		if strings.HasPrefix(s, exc) {
			return true
		}
	}
	return false
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
