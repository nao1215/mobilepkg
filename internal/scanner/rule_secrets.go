package scanner

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/nao1215/mobilepkg/internal/secrets"
)

type hardcodedSecretsRule struct{}

func (r *hardcodedSecretsRule) Name() string { return "HardcodedSecrets" }

// Strings that are common in DEX but should not trigger findings.
var secretExclusions = []string{
	"com.google.android",
	"android.permission",
	"android.intent",
	"http://schemas.android.com",
	"http://www.w3.org",
	"http://ns.adobe.com",
	"http://xmlpull.org",
	// Documentation and specification URLs
	"http://developer.android.com",
	"http://developer.apple.com",
	"https://developer.android.com",
	"https://developer.apple.com",
	"https://www.googleapis.com/auth/",
	// Common library/SDK constants that embed API key patterns
	"https://firebase.google.com",
	"https://play.google.com",
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

			for _, sp := range secrets.Patterns {
				match := sp.Re.FindString(s)
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
					ID:          fmt.Sprintf("dex.secret.%s.%s", sp.Kind, hashID),
					Category:    "dex_secret",
					Severity:    sp.Severity,
					Confidence:  sp.Confidence,
					Message:     fmt.Sprintf("potential %s found in DEX string table", sp.Kind),
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
