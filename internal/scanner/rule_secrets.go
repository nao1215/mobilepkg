package scanner

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
)

type hardcodedSecretsRule struct{}

func (r *hardcodedSecretsRule) Name() string { return "HardcodedSecrets" }

// secretPattern defines a regex pattern for detecting potential secrets in DEX strings.
type secretPattern struct {
	kind       string
	pattern    *regexp.Regexp
	severity   string
	confidence string
}

// dexSecretPatterns is the unified set of secret patterns used for DEX string
// scanning. It mirrors the patterns in the root analyze.go secretPatterns to
// ensure consistent detection across manifest/plist and DEX sources.
var dexSecretPatterns = []secretPattern{
	{"aws_key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "error", "high"},
	{"gcp_api_key", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`), "error", "high"},
	{"github_token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`), "error", "high"},
	{"private_key", regexp.MustCompile(`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`), "error", "high"},
	{"firebase_url", regexp.MustCompile(`https://[a-z0-9-]+\.firebaseio\.com`), "warn", "medium"},
	{"generic_api_key", regexp.MustCompile(`(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["']?([A-Za-z0-9_\-]{20,})["']?`), "warn", "medium"},
	{"bearer_token", regexp.MustCompile(`Bearer\s+[A-Za-z0-9_\-\.]{20,}`), "warn", "medium"},
	{"generic_secret", regexp.MustCompile(`(?i)(?:secret|password|passwd|token|credential)\s*[=:]\s*["']([^"']{8,})["']`), "warn", "low"},
}

// Strings that are common in DEX but should not trigger findings.
var secretExclusions = []string{
	"com.google.android",
	"android.permission",
	"android.intent",
	"http://schemas.android.com",
	"http://www.w3.org",
	"http://ns.adobe.com",
	"http://xmlpull.org",
}

func (r *hardcodedSecretsRule) Match(ctx *Context) []Finding {
	var findings []Finding
	seen := make(map[string]struct{})

	for i, df := range ctx.DexFiles {
		for _, s := range df.Strings() {
			if len(s) < 10 || len(s) > 2048 {
				continue
			}
			if isExcludedString(s) {
				continue
			}

			for _, sp := range dexSecretPatterns {
				match := sp.pattern.FindString(s)
				if match == "" {
					continue
				}
				// Deduplicate across DEX files.
				if _, ok := seen[match]; ok {
					continue
				}
				seen[match] = struct{}{}

				// Use hash-based ID instead of raw secret prefix.
				h := sha256.Sum256([]byte(match))
				hashID := fmt.Sprintf("%x", h[:6])

				findings = append(findings, Finding{
					ID:          fmt.Sprintf("dex.secret.%s.%s", sp.kind, hashID),
					Category:    "dex_secret",
					Severity:    sp.severity,
					Confidence:  sp.confidence,
					Message:     fmt.Sprintf("potential %s found in DEX string table", sp.kind),
					ArchivePath: ctx.dexName(i),
					Field:       "string_table",
					Matched:     match,
				})
				break // One match per string is enough.
			}
		}
	}
	return findings
}

func isExcludedString(s string) bool {
	for _, exc := range secretExclusions {
		if strings.Contains(s, exc) {
			return true
		}
	}
	return false
}

func sanitizeID(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('.')
		}
	}
	return b.String()
}
