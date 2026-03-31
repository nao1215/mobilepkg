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
// These are XML namespace URIs, specification references, and example domains
// that are not actual cleartext traffic destinations.
var cleartextExclusions = []string{
	"http://schemas.android.com",
	"http://www.w3.org",
	"http://ns.adobe.com",
	"http://xmlpull.org",
	"http://java.sun.com",
	"http://xml.org",
	"http://www.xml.org",
	"http://apache.org",
	"http://www.apache.org",
	"http://example.com",
	"http://example.org",
	"http://purl.org",
	"http://json-schema.org",
	"http://www.json.org",
	"http://docs.oasis-open.org",
	"http://relaxng.org",
	"http://schemas.microsoft.com",
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
	return true
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
