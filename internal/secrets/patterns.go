// Package secrets defines shared secret-detection patterns used by both
// the manifest/plist scanner (root package) and the DEX string scanner.
// Keeping a single definition prevents the two lists from diverging.
package secrets

import "regexp"

// Severity constants for secret patterns.
const (
	SevError = "error"
	SevWarn  = "warn"
)

// Confidence constants for secret patterns.
const (
	ConfHigh   = "high"
	ConfMedium = "medium"
	ConfLow    = "low"
)

// Pattern defines a regex pattern for detecting potential secrets.
type Pattern struct {
	Kind       string
	Re         *regexp.Regexp
	Severity   string // "error", "warn"
	Confidence string // "high", "medium", "low"
}

// Patterns is the canonical list of secret-detection patterns.
// Both the root-package secret scanner and the DEX scanner reference this.
var Patterns = []Pattern{
	{"aws_key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), SevError, ConfHigh},
	{"gcp_api_key", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`), SevError, ConfHigh},
	{"github_token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`), SevError, ConfHigh},
	{"private_key", regexp.MustCompile(`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`), SevError, ConfHigh},
	{"firebase_url", regexp.MustCompile(`https://[a-z0-9-]+\.firebaseio\.com`), SevWarn, ConfMedium},
	{"generic_api_key", regexp.MustCompile(`(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["']?([A-Za-z0-9_\-]{20,})["']?`), SevWarn, ConfMedium},
	{"bearer_token", regexp.MustCompile(`Bearer\s+[A-Za-z0-9_\-\.]{20,}`), SevWarn, ConfMedium},
	{"generic_secret", regexp.MustCompile(`(?i)(?:secret|password|passwd|token|credential)\s*[=:]\s*["']([^"']{8,})["']`), SevWarn, ConfLow},
}
