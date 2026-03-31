// Package scanner provides a security rule engine for analyzing Android
// application packages using parsed DEX bytecode and manifest data. It
// produces findings compatible with the mobilepkg analysis pipeline.
package scanner

import (
	"fmt"

	"github.com/nao1215/mobilepkg/internal/dex"
)

// Severity and confidence string constants used across scanner rules.
const (
	sevError = "error"
	sevWarn  = "warn"
	sevInfo  = "info"

	confHigh   = "high"
	confMedium = "medium"
	confLow    = "low"
)

// adjustForLibrary lowers severity and confidence when the caller belongs
// to a well-known library. Returns the adjusted severity, confidence, and
// formatted message.
func adjustForLibrary(callerClass, baseSeverity, baseMessage string) (severity, confidence, message string) {
	if !isKnownLibraryClass(callerClass) {
		return baseSeverity, confHigh, fmt.Sprintf("%s (in %s)", baseMessage, callerClass)
	}
	sev := baseSeverity
	if sev == sevError {
		sev = sevWarn
	}
	return sev, confMedium, fmt.Sprintf("%s (in library %s)", baseMessage, callerClass)
}

// Finding represents a security observation from a scanner rule.
// Fields use plain types to avoid circular imports with the root package.
type Finding struct {
	ID          string
	Category    string
	Severity    string // "info", "warn", "error"
	Confidence  string // "high", "medium", "low"
	Message     string
	ArchivePath string
	Field       string
	Matched     string
	Offset      int
}

// Context provides all data that rules need to inspect.
type Context struct {
	DexFiles []*dex.File
	// DexNames holds the archive entry name for each DexFile (same index).
	// Used to populate Finding.ArchivePath with the correct file name.
	DexNames []string

	// allStrings is the deduplicated union of all DEX string tables.
	// Populated lazily by MergedStrings().
	allStrings     map[string]struct{}
	allStringsInit bool
}

// dexName returns the archive name for the DEX file at the given index.
func (c *Context) dexName(i int) string {
	if i < len(c.DexNames) && c.DexNames[i] != "" {
		return c.DexNames[i]
	}
	return "classes.dex"
}

// MergedStrings returns the deduplicated set of strings from all DEX files.
func (c *Context) MergedStrings() map[string]struct{} {
	if c.allStringsInit {
		return c.allStrings
	}
	c.allStrings = make(map[string]struct{})
	for _, df := range c.DexFiles {
		for _, s := range df.Strings() {
			c.allStrings[s] = struct{}{}
		}
	}
	c.allStringsInit = true
	return c.allStrings
}

// Rule is the interface that all security detection rules implement.
type Rule interface {
	Name() string
	Match(ctx *Context) []Finding
}

// DefaultRules returns the standard set of security detection rules.
func DefaultRules() []Rule {
	return []Rule{
		&hardcodedSecretsRule{},
		&insecureWebViewRule{},
		&cleartextTrafficRule{},
		&dangerousAPIsRule{},
	}
}

// Scan runs all default rules against the given context and returns
// the aggregated findings.
func Scan(ctx *Context) []Finding {
	return ScanWithRules(ctx, DefaultRules())
}

// ScanWithRules runs the given rules against the context and returns
// the aggregated findings.
func ScanWithRules(ctx *Context, rules []Rule) []Finding {
	findings := make([]Finding, 0, len(rules))
	for _, r := range rules {
		findings = append(findings, r.Match(ctx)...)
	}
	return findings
}
