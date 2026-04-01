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

// excludedHosts is a set of hostnames whose http:// URLs should not
// produce cleartext findings. These fall into three categories:
//   - XML namespace / schema authorities (schemas.android.com, www.w3.org)
//   - Specification / documentation sites (dashif.org, semver.org)
//   - RFC 2606 / 6761 reserved example domains (example.com/org/net)
//
// Matching is done on the parsed hostname (exact match), so
// "developer.android.com.attacker.example" is NOT excluded.
var excludedHosts = map[string]struct{}{
	// XML/schema namespaces
	"schemas.android.com":    {},
	"www.w3.org":             {},
	"ns.adobe.com":           {},
	"xmlpull.org":            {},
	"java.sun.com":           {},
	"xml.org":                {},
	"www.xml.org":            {},
	"apache.org":             {},
	"www.apache.org":         {},
	"purl.org":               {},
	"json-schema.org":        {},
	"www.json.org":           {},
	"docs.oasis-open.org":    {},
	"relaxng.org":            {},
	"schemas.microsoft.com":  {},
	"schemas.xmlsoap.org":    {},
	"www.ietf.org":           {},
	"tools.ietf.org":         {},
	"www.iso.org":            {},
	// Example/test domains (RFC 2606 / RFC 6761)
	"example.com":     {},
	"example.org":     {},
	"example.net":     {},
	"www.example.com": {},
	"www.example.org": {},
	"www.example.net": {},
	// Specification and documentation sites
	"dashif.org":              {},
	"www.dashif.org":          {},
	"id3.org":                 {},
	"www.id3.org":             {},
	"www.unicode.org":         {},
	"www.rfc-editor.org":      {},
	"semver.org":              {},
	"opensource.org":           {},
	"creativecommons.org":     {},
	"developer.android.com":   {},
	"developer.apple.com":     {},
	// Logging/library documentation
	"logback.qos.ch":    {},
	"logging.apache.org": {},
	"slf4j.org":          {},
	"www.slf4j.org":      {},
	// SDK schema namespaces
	"schemas.applovin.com": {},
	// Specification URLs
	"specs.openid.net": {},
	"openid.net":       {},
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
			if _, ok := excludedHosts[strings.ToLower(host)]; ok {
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
	// Filter Java/Kotlin class names that URL-parse as hostnames.
	// Real hostnames are conventionally lowercase; a label starting
	// with an uppercase letter (e.g. "javax.xml.XMLConstants") is
	// almost certainly a class name, not a network destination.
	if looksLikeJavaClassName(host) {
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

// looksLikeJavaClassName returns true if the hostname contains a label
// starting with an uppercase letter, which indicates a Java/Kotlin class
// name that URL-parsed as a hostname (e.g. "javax.xml.XMLConstants").
func looksLikeJavaClassName(host string) bool {
	for _, label := range strings.Split(host, ".") {
		if len(label) > 0 && label[0] >= 'A' && label[0] <= 'Z' {
			return true
		}
	}
	return false
}

// isBareTLD returns true if the host is a bare top-level domain.
func isBareTLD(host string) bool {
	_, ok := commonTLDs[strings.ToLower(host)]
	return ok
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
