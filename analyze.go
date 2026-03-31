package mobilepkg

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// analyzeReport performs security analysis on an inspection [report] and
// returns an analysisResult containing findings, secret candidates,
// and an optional baseline diff. This function is called internally by
// [InspectFile]; most callers do not need to use it directly.
//
// The report itself is not modified. Analysis is a separate layer from
// extraction — expert callers who need only raw facts can use
// extractReport (internal) and call this function manually.
func analyzeReport(rpt report, opts analyzeOptions) analysisResult {
	result := analysisResult{report: rpt}

	result.findings = append(result.findings, analyzeManifestSecurity(rpt)...)
	result.findings = append(result.findings, analyzeExportedComponents(rpt.ExportedComponents)...)
	result.findings = append(result.findings, analyzeSigningInfo(rpt.Signing)...)
	result.findings = append(result.findings, analyzeDangerousPermissions(rpt)...)
	result.findings = append(result.findings, analyzeIOSEntitlements(rpt)...)
	result.findings = append(result.findings, analyzeNSCPolicy(rpt)...)
	result.findings = append(result.findings, analyzeIOSATS(rpt)...)

	// DEX-based security scanning for Android.
	if rpt.Platform == PlatformAndroid && len(opts.dexReaders) > 0 {
		dexFindings, dexDiags := analyzeDex(opts.dexReaders, rpt.Format, opts.maxEntryBytes)
		result.findings = append(result.findings, dexFindings...)
		result.report.Diagnostics = append(result.report.Diagnostics, dexDiags...)
	}

	// Extract deep link endpoints from exported component intent-filters.
	result.report.NetworkEndpoints = append(result.report.NetworkEndpoints,
		extractDeepLinkEndpoints(rpt.ExportedComponents)...)

	// Scan for secrets in platform data.
	if ar, ok := asAndroid(rpt); ok && ar.RawManifest != nil {
		result.secretCandidates = append(result.secretCandidates, scanSecretsInMap(ar.RawManifest, "manifest")...)
	}
	if ir, ok := asIOS(rpt); ok {
		if ir.InfoPlist != nil {
			result.secretCandidates = append(result.secretCandidates, scanSecretsInMap(ir.InfoPlist, "info_plist")...)
		}
		if ir.Entitlements != nil {
			result.secretCandidates = append(result.secretCandidates, scanSecretsInMap(ir.Entitlements, "entitlement")...)
		}
	}

	// Baseline diff.
	if opts.baseline != nil {
		d := diffReports(*opts.baseline, rpt)
		result.diff = &d
	}

	// Sort for stable output.
	sort.Slice(result.findings, func(i, j int) bool {
		return result.findings[i].ID < result.findings[j].ID
	})
	sort.Slice(result.secretCandidates, func(i, j int) bool {
		if result.secretCandidates[i].Kind != result.secretCandidates[j].Kind {
			return result.secretCandidates[i].Kind < result.secretCandidates[j].Kind
		}
		return result.secretCandidates[i].Source < result.secretCandidates[j].Source
	})

	return result
}

// analyzeManifestSecurity generates findings for dangerous manifest attributes.
func analyzeManifestSecurity(r report) []Finding {
	if r.Platform != PlatformAndroid {
		return nil
	}

	var findings []Finding

	if r.Debuggable {
		findings = append(findings, Finding{
			ID:         "manifest.debuggable",
			Category:   "manifest",
			Severity:   SeverityError,
			Confidence: ConfidenceHigh,
			Message:    "application is debuggable — allows arbitrary code execution via adb on any device",
			Evidence: []Evidence{{
				ArchivePath: "AndroidManifest.xml",
				Field:       "application[@debuggable]",
			}},
			Fingerprint: fingerprint("manifest", "debuggable"),
		})
	}

	if r.AllowBackup {
		findings = append(findings, Finding{
			ID:         "manifest.allow_backup",
			Category:   "manifest",
			Severity:   SeverityWarn,
			Confidence: ConfidenceHigh,
			Message:    "application allows backup — app data can be extracted via adb backup",
			Evidence: []Evidence{{
				ArchivePath: "AndroidManifest.xml",
				Field:       "application[@allowBackup]",
			}},
			Fingerprint: fingerprint("manifest", "allowBackup"),
		})
	}

	if r.UsesCleartextTraffic {
		findings = append(findings, Finding{
			ID:         "manifest.cleartext_traffic",
			Category:   "manifest",
			Severity:   SeverityWarn,
			Confidence: ConfidenceHigh,
			Message:    "application permits cleartext (HTTP) traffic — network communication may be intercepted",
			Evidence: []Evidence{{
				ArchivePath: "AndroidManifest.xml",
				Field:       "application[@usesCleartextTraffic]",
			}},
			Fingerprint: fingerprint("manifest", "usesCleartextTraffic"),
		})
	}

	if r.TestOnly {
		findings = append(findings, Finding{
			ID:         "manifest.test_only",
			Category:   "manifest",
			Severity:   SeverityError,
			Confidence: ConfidenceHigh,
			Message:    "application is testOnly — can only be installed via adb, not suitable for production",
			Evidence: []Evidence{{
				ArchivePath: "AndroidManifest.xml",
				Field:       "application[@testOnly]",
			}},
			Fingerprint: fingerprint("manifest", "testOnly"),
		})
	}

	if r.ProfileableByShell {
		findings = append(findings, Finding{
			ID:         "manifest.profileable_by_shell",
			Category:   "manifest",
			Severity:   SeverityWarn,
			Confidence: ConfidenceHigh,
			Message:    "application is profileable from shell — may leak performance data in production",
			Evidence: []Evidence{{
				ArchivePath: "AndroidManifest.xml",
				Field:       "application[@profileableByShell]",
			}},
			Fingerprint: fingerprint("manifest", "profileableByShell"),
		})
	}

	return findings
}

// analyzeExportedComponents generates findings for exported components.
func analyzeExportedComponents(components []ExportedComponent) []Finding {
	var findings []Finding
	for _, ec := range components {
		if !ec.Exported {
			continue
		}

		// Determine severity based on component type and protection.
		severity := SeverityInfo
		hasProtection := ec.Permission != "" || ec.ReadPermission != "" || ec.WritePermission != ""
		isBrowsable := componentIsBrowsable(ec)
		isProvider := ec.Kind == "provider"

		switch {
		case isProvider && !hasProtection:
			severity = SeverityError
		case isProvider:
			severity = SeverityWarn
		case !hasProtection && (ec.Kind == "service" || ec.Kind == "receiver"):
			severity = SeverityWarn
		case !hasProtection && ec.Kind == "activity" && isBrowsable:
			severity = SeverityWarn
		}

		msg := fmt.Sprintf("exported %s: %s", ec.Kind, ec.Name)
		if ec.Permission != "" {
			msg += fmt.Sprintf(" (requires %s)", ec.Permission)
		} else if !hasProtection {
			msg += " (no permission required)"
		}
		if isBrowsable {
			msg += " [browsable]"
		}
		if ec.Authorities != "" {
			msg += fmt.Sprintf(" [authorities: %s]", ec.Authorities)
		}
		if isProvider && ec.GrantURIPermissions {
			msg += " [grantUriPermissions]"
		}

		findings = append(findings, Finding{
			ID:         fmt.Sprintf("exported.%s.%s", ec.Kind, sanitizeFindingID(ec.Name)),
			Category:   "exported_component",
			Severity:   severity,
			Confidence: ConfidenceHigh,
			Message:    msg,
			Evidence: []Evidence{{
				ArchivePath:       "AndroidManifest.xml",
				Field:             fmt.Sprintf("%s[@name]", ec.Kind),
				MatchedTextMasked: ec.Name,
			}},
			Fingerprint: fingerprint("exported", ec.Kind, ec.Name),
		})
	}
	return findings
}

// componentIsBrowsable returns true if the component has a browsable intent-filter.
func componentIsBrowsable(ec ExportedComponent) bool {
	for _, f := range ec.IntentFilters {
		for _, cat := range f.Categories {
			if cat == "android.intent.category.BROWSABLE" {
				return true
			}
		}
	}
	return false
}

// analyzeSigningInfo generates findings from signing certificate information.
func analyzeSigningInfo(signing *SigningInfo) []Finding {
	if signing == nil {
		return nil
	}

	var findings []Finding
	now := time.Now()

	// V1-only signing is weak — it does not protect against APK modifications.
	if signing.Scheme == "v1" {
		findings = append(findings, Finding{
			ID:         "signing.v1_only",
			Category:   "signing",
			Severity:   SeverityWarn,
			Confidence: ConfidenceHigh,
			Message:    "APK uses v1 (JAR) signing only — vulnerable to modification without invalidating signature",
			Evidence: []Evidence{{
				Field:             "signing.scheme",
				MatchedTextMasked: signing.Scheme,
			}},
			Fingerprint: fingerprint("signing.v1_only"),
		})
	}

	for _, cert := range signing.Certificates {
		// Detect debug/self-signed certificates.
		if isDebugCert(cert) {
			findings = append(findings, Finding{
				ID:         "signing.debug_cert",
				Category:   "signing",
				Severity:   SeverityError,
				Confidence: ConfidenceHigh,
				Message:    fmt.Sprintf("signed with debug certificate (subject: %s) — not suitable for production", cert.Subject),
				Evidence: []Evidence{{
					Field:             "certificate.subject",
					MatchedTextMasked: cert.Subject,
				}},
				Fingerprint: fingerprint("signing.debug", cert.SHA256Fingerprint),
			})
		}

		// Detect self-signed test certificates (not debug but still self-signed).
		if cert.SelfSigned && !isDebugCert(cert) {
			findings = append(findings, Finding{
				ID:         "signing.self_signed_test_cert",
				Category:   "signing",
				Severity:   SeverityWarn,
				Confidence: ConfidenceMedium,
				Message:    fmt.Sprintf("self-signed certificate (subject: %s) — may indicate a test build", cert.Subject),
				Evidence: []Evidence{{
					Field:             "certificate.subject",
					MatchedTextMasked: cert.Subject,
				}},
				Fingerprint: fingerprint("signing.self_signed", cert.SHA256Fingerprint),
			})
		}

		// Detect weak signature digest algorithms.
		if isWeakDigest(cert.SignatureAlgorithm) {
			findings = append(findings, Finding{
				ID:         "signing.weak_digest",
				Category:   "signing",
				Severity:   SeverityWarn,
				Confidence: ConfidenceHigh,
				Message:    fmt.Sprintf("certificate uses weak signature algorithm: %s", cert.SignatureAlgorithm),
				Evidence: []Evidence{{
					Field:             "certificate.signature_algorithm",
					MatchedTextMasked: cert.SignatureAlgorithm,
				}},
				Fingerprint: fingerprint("signing.weak_digest", cert.SHA256Fingerprint),
			})
		}

		// Detect weak key sizes.
		if isWeakKeySize(cert.PublicKeyAlgorithm, cert.KeySize) {
			findings = append(findings, Finding{
				ID:         "signing.weak_key_size",
				Category:   "signing",
				Severity:   SeverityWarn,
				Confidence: ConfidenceHigh,
				Message:    fmt.Sprintf("certificate uses weak key: %s %d-bit", cert.PublicKeyAlgorithm, cert.KeySize),
				Evidence: []Evidence{{
					Field:             "certificate.key_size",
					MatchedTextMasked: fmt.Sprintf("%s %d", cert.PublicKeyAlgorithm, cert.KeySize),
				}},
				Fingerprint: fingerprint("signing.weak_key", cert.SHA256Fingerprint),
			})
		}

		// Detect expired certificates.
		if cert.NotAfter != "" {
			expiry, err := time.Parse(time.RFC3339, cert.NotAfter)
			if err == nil && now.After(expiry) {
				findings = append(findings, Finding{
					ID:         fmt.Sprintf("signing.expired.%s", sanitizeFindingID(cert.SHA256Fingerprint)),
					Category:   "signing",
					Severity:   SeverityWarn,
					Confidence: ConfidenceHigh,
					Message:    fmt.Sprintf("signing certificate expired: %s (subject: %s)", cert.NotAfter, cert.Subject),
					Evidence: []Evidence{{
						Field:             "certificate.not_after",
						MatchedTextMasked: cert.NotAfter,
					}},
					Fingerprint: fingerprint("signing.expired", cert.SHA256Fingerprint),
				})
			}
		}
	}
	return findings
}

// isWeakDigest returns true for signature algorithms using MD5 or SHA-1.
func isWeakDigest(algo string) bool {
	if algo == "" {
		return false
	}
	lower := strings.ToLower(algo)
	return strings.Contains(lower, "md5") || strings.Contains(lower, "md2") ||
		(strings.Contains(lower, "sha1") || strings.Contains(lower, "sha-1"))
}

// isWeakKeySize returns true for key sizes considered too small.
func isWeakKeySize(algo string, bits int) bool {
	if bits == 0 {
		return false
	}
	switch strings.ToUpper(algo) {
	case "RSA":
		return bits < 2048
	case "ECDSA":
		return bits < 256
	case "DSA":
		return bits < 2048
	}
	return false
}

// isDebugCert heuristically detects debug/development signing certificates.
func isDebugCert(cert CertSummary) bool {
	subj := strings.ToLower(cert.Subject)
	issuer := strings.ToLower(cert.Issuer)

	// Android Studio debug keystore uses "Android Debug" as CN.
	if strings.Contains(subj, "android debug") {
		return true
	}
	// Self-signed with generic debug-like names.
	if cert.Subject == cert.Issuer &&
		(strings.Contains(subj, "debug") || strings.Contains(subj, "test") ||
			subj == "unknown" || subj == "cn=unknown") {
		return true
	}
	_ = issuer
	return false
}

// dangerousAndroidPermissions maps raw Android permission names to short
// descriptions for permissions that pose elevated risk.
var dangerousAndroidPermissions = map[string]string{
	"android.permission.READ_SMS":                 "can read SMS messages",
	"android.permission.SEND_SMS":                 "can send SMS messages",
	"android.permission.RECEIVE_SMS":              "can intercept incoming SMS",
	"android.permission.READ_CALL_LOG":            "can read call history",
	"android.permission.READ_CONTACTS":            "can read contacts",
	"android.permission.WRITE_CONTACTS":           "can modify contacts",
	"android.permission.CAMERA":                   "can access the camera",
	"android.permission.RECORD_AUDIO":             "can record audio via microphone",
	"android.permission.ACCESS_FINE_LOCATION":     "can access precise GPS location",
	"android.permission.READ_EXTERNAL_STORAGE":    "can read external storage",
	"android.permission.WRITE_EXTERNAL_STORAGE":   "can write to external storage",
	"android.permission.READ_PHONE_STATE":         "can read device identifiers and call state",
	"android.permission.CALL_PHONE":               "can initiate phone calls without user interaction",
	"android.permission.SYSTEM_ALERT_WINDOW":      "can draw overlay windows on top of other apps",
	"android.permission.REQUEST_INSTALL_PACKAGES": "can request to install APKs",
}

// analyzeDangerousPermissions generates findings for dangerous permissions.
func analyzeDangerousPermissions(r report) []Finding {
	var findings []Finding
	for _, p := range r.Permissions {
		desc, ok := dangerousAndroidPermissions[p.RawName]
		if !ok {
			continue
		}
		findings = append(findings, Finding{
			ID:         "perm.dangerous." + sanitizeFindingID(p.RawName),
			Category:   "permission",
			Severity:   SeverityInfo,
			Confidence: ConfidenceHigh,
			Message:    fmt.Sprintf("dangerous permission %s — %s", p.RawName, desc),
			Evidence: []Evidence{{
				ArchivePath:       "AndroidManifest.xml",
				Field:             "uses-permission",
				MatchedTextMasked: p.RawName,
			}},
			Fingerprint: fingerprint("perm.dangerous", p.RawName),
		})
	}
	return findings
}

// analyzeIOSEntitlements generates findings from iOS entitlements that
// indicate security-relevant configuration.
func analyzeIOSEntitlements(r report) []Finding {
	if r.Platform != PlatformIOS {
		return nil
	}
	ir, ok := asIOS(r)
	if !ok || ir.Entitlements == nil {
		// Entitlements may also be carried via permissions with source "entitlement".
		return analyzeIOSEntitlementsFromPermissions(r)
	}
	var findings []Finding

	// get-task-allow = true means a debug/development build.
	if v, ok := ir.Entitlements["get-task-allow"]; ok {
		if b, ok := v.(bool); ok && b {
			findings = append(findings, Finding{
				ID:         "ios.get_task_allow",
				Category:   "entitlement",
				Severity:   SeverityError,
				Confidence: ConfidenceHigh,
				Message:    "get-task-allow is true — this is a debug build, debugger can attach to the process",
				Evidence: []Evidence{{
					ArchivePath: "embedded.mobileprovision",
					Field:       "get-task-allow",
				}},
				Fingerprint: fingerprint("ios", "get-task-allow"),
			})
		}
	}

	return findings
}

// analyzeIOSEntitlementsFromPermissions checks for entitlement-based findings
// when PlatformData is not available (e.g. when SectionPlatformRaw was not requested).
func analyzeIOSEntitlementsFromPermissions(r report) []Finding {
	var findings []Finding
	for _, p := range r.Permissions {
		if p.Source == "entitlement" && p.RawName == "get-task-allow" {
			findings = append(findings, Finding{
				ID:         "ios.get_task_allow",
				Category:   "entitlement",
				Severity:   SeverityError,
				Confidence: ConfidenceHigh,
				Message:    "get-task-allow entitlement present — likely a debug build",
				Evidence: []Evidence{{
					ArchivePath: "embedded.mobileprovision",
					Field:       "get-task-allow",
				}},
				Fingerprint: fingerprint("ios", "get-task-allow"),
			})
		}
	}
	return findings
}

// extractEndpointsFromPlist extracts network endpoints from an iOS Info.plist.
func extractEndpointsFromPlist(info map[string]any) []NetworkEndpoint {
	var endpoints []NetworkEndpoint

	if ats, ok := info["NSAppTransportSecurity"].(map[string]any); ok {
		if domains, ok := ats["NSExceptionDomains"].(map[string]any); ok {
			for domain := range domains {
				endpoints = append(endpoints, NetworkEndpoint{
					Scheme:     "https",
					Host:       domain,
					Source:     "info_plist",
					Confidence: ConfidenceHigh,
				})
			}
		}
	}

	if urlTypes, ok := info["CFBundleURLTypes"].([]any); ok {
		for _, t := range urlTypes {
			if dict, ok := t.(map[string]any); ok {
				if schemes, ok := dict["CFBundleURLSchemes"].([]any); ok {
					for _, s := range schemes {
						if scheme, ok := s.(string); ok {
							endpoints = append(endpoints, NetworkEndpoint{
								Scheme:     scheme,
								Host:       "(custom URL scheme)",
								Source:     "info_plist",
								Confidence: ConfidenceHigh,
							})
						}
					}
				}
			}
		}
	}

	return endpoints
}

// extractEndpointsFromEntitlements extracts network-related info from entitlements.
func extractEndpointsFromEntitlements(entitlements map[string]any) []NetworkEndpoint {
	var endpoints []NetworkEndpoint

	if domains, ok := entitlements["com.apple.developer.associated-domains"].([]any); ok {
		for _, d := range domains {
			if s, ok := d.(string); ok {
				parts := strings.SplitN(s, ":", 2)
				if len(parts) == 2 {
					endpoints = append(endpoints, NetworkEndpoint{
						Scheme:     parts[0],
						Host:       parts[1],
						Source:     "entitlement",
						Confidence: ConfidenceHigh,
					})
				}
			}
		}
	}

	return endpoints
}

// extractDeepLinkEndpoints extracts network endpoints from intent-filter
// data specifications in exported components. Deep links declared via
// intent-filters are security-relevant because they expose the app to
// external URI invocations.
//
// The function deduplicates entries by normalized scheme+host+path and
// skips entries that have no meaningful host (e.g. scheme-only or wildcard).
func extractDeepLinkEndpoints(components []ExportedComponent) []NetworkEndpoint {
	var endpoints []NetworkEndpoint
	seen := make(map[string]struct{})

	for _, ec := range components {
		for _, f := range ec.IntentFilters {
			for _, d := range f.Data {
				if d.Scheme == "" && d.Host == "" {
					continue
				}
				host := d.Host
				if host == "" || host == "*" {
					// Scheme-only entries (no host) and wildcard hosts
					// are not meaningful as network endpoints.
					continue
				}

				scheme := strings.ToLower(d.Scheme)
				key := scheme + "://" + strings.ToLower(host) + d.Path
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}

				endpoints = append(endpoints, NetworkEndpoint{
					Scheme:     d.Scheme,
					Host:       host,
					Path:       d.Path,
					Source:     "intent_filter",
					Confidence: ConfidenceHigh,
				})
			}
		}
	}
	return endpoints
}

// secretPatterns defines regex patterns for detecting potential secrets.
// This list is shared by both manifest/plist scanning and DEX string scanning
// to ensure consistent detection across all sources.
var secretPatterns = []struct {
	kind       string
	pattern    *regexp.Regexp
	confidence Confidence
}{
	{"aws_key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), ConfidenceHigh},
	{"gcp_api_key", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`), ConfidenceHigh},
	{"github_token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`), ConfidenceHigh},
	{"private_key", regexp.MustCompile(`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`), ConfidenceHigh},
	{"firebase_url", regexp.MustCompile(`https://[a-z0-9-]+\.firebaseio\.com`), ConfidenceMedium},
	{"api_key", regexp.MustCompile(`(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["']?([A-Za-z0-9_\-]{20,})["']?`), ConfidenceMedium},
	{"bearer_token", regexp.MustCompile(`Bearer\s+[A-Za-z0-9_\-\.]{20,}`), ConfidenceMedium},
	{"generic_secret", regexp.MustCompile(`(?i)(?:secret|password|passwd|token|credential)\s*[=:]\s*["']([^"']{8,})["']`), ConfidenceLow},
}

func scanSecretsInStrings(kvPairs map[string]string, source string) []SecretCandidate {
	var candidates []SecretCandidate
	for key, value := range kvPairs {
		for _, sp := range secretPatterns {
			if sp.pattern.MatchString(value) || sp.pattern.MatchString(key+"="+value) {
				candidates = append(candidates, SecretCandidate{
					Kind:        sp.kind,
					MaskedValue: maskSecret(value),
					Source:      source,
					Confidence:  sp.confidence,
				})
				break
			}
		}
	}
	return candidates
}

func scanSecretsInMap(m map[string]any, source string) []SecretCandidate {
	flat := flattenMap(m, "")
	return scanSecretsInStrings(flat, source)
}

func flattenMap(m map[string]any, prefix string) map[string]string {
	result := make(map[string]string)
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch val := v.(type) {
		case string:
			result[key] = val
		case map[string]any:
			for fk, fv := range flattenMap(val, key) {
				result[fk] = fv
			}
		case []any:
			for i, item := range val {
				elemKey := fmt.Sprintf("%s[%d]", key, i)
				switch elem := item.(type) {
				case string:
					result[elemKey] = elem
				case map[string]any:
					for fk, fv := range flattenMap(elem, elemKey) {
						result[fk] = fv
					}
				}
			}
		}
	}
	return result
}

func maskSecret(value string) string {
	if len(value) <= 4 {
		return "****"
	}
	visible := len(value) / 4
	if visible < 2 {
		visible = 2
	}
	if visible > 3 {
		visible = 3
	}
	return value[:visible] + strings.Repeat("*", len(value)-visible)
}

// fingerprint computes a stable fingerprint from the given components.
// The comparison key for baseline is always ID + Fingerprint.
func fingerprint(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return fmt.Sprintf("%x", h[:8])
}

func sanitizeFindingID(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			return r
		}
		return '.'
	}, s)
}

// analyzeNSCPolicy generates findings from the parsed network security config.
func analyzeNSCPolicy(r report) []Finding {
	if r.Platform != PlatformAndroid || r.NSCPolicy == nil {
		return nil
	}
	var findings []Finding
	nsc := r.NSCPolicy

	// Base config allows cleartext.
	if nsc.CleartextPermitted {
		findings = append(findings, Finding{
			ID:         "nsc.base_config_cleartext",
			Category:   "cleartext",
			Severity:   SeverityWarn,
			Confidence: ConfidenceHigh,
			Message:    "network security config base-config permits cleartext traffic",
			Evidence: []Evidence{{
				ArchivePath: "network_security_config.xml",
				Field:       "base-config[@cleartextTrafficPermitted]",
			}},
			Fingerprint: fingerprint("nsc", "base_config_cleartext"),
		})
	}

	// Domain configs that allow cleartext.
	for _, dc := range nsc.DomainConfigs {
		findings = append(findings, analyzeNSCDomainConfig(dc)...)
	}

	// Debug overrides present.
	if nsc.HasDebugOverrides {
		findings = append(findings, Finding{
			ID:         "nsc.debug_overrides",
			Category:   "cleartext",
			Severity:   SeverityWarn,
			Confidence: ConfidenceHigh,
			Message:    "network security config contains debug-overrides — may weaken TLS validation in debug builds",
			Evidence: []Evidence{{
				ArchivePath: "network_security_config.xml",
				Field:       "debug-overrides",
			}},
			Fingerprint: fingerprint("nsc", "debug_overrides"),
		})
	}

	return findings
}

// analyzeNSCDomainConfig recursively generates findings from domain-configs.
func analyzeNSCDomainConfig(dc DomainConfig) []Finding {
	var findings []Finding
	if dc.CleartextPermitted && len(dc.Domains) > 0 {
		domains := strings.Join(dc.Domains, ", ")
		findings = append(findings, Finding{
			ID:         fmt.Sprintf("nsc.domain_cleartext.%s", sanitizeFindingID(dc.Domains[0])),
			Category:   "cleartext",
			Severity:   SeverityWarn,
			Confidence: ConfidenceHigh,
			Message:    fmt.Sprintf("network security config permits cleartext traffic for: %s", domains),
			Evidence: []Evidence{{
				ArchivePath:       "network_security_config.xml",
				Field:             "domain-config[@cleartextTrafficPermitted]",
				MatchedTextMasked: domains,
			}},
			Fingerprint: fingerprint("nsc", "domain_cleartext", dc.Domains[0]),
		})
	}
	for _, nested := range dc.NestedConfigs {
		findings = append(findings, analyzeNSCDomainConfig(nested)...)
	}
	return findings
}

// analyzeIOSATS generates findings from iOS App Transport Security settings.
func analyzeIOSATS(r report) []Finding {
	if r.Platform != PlatformIOS {
		return nil
	}
	ir, ok := asIOS(r)
	if !ok || ir.InfoPlist == nil {
		return nil
	}

	ats, ok := ir.InfoPlist["NSAppTransportSecurity"].(map[string]any)
	if !ok {
		return nil
	}

	var findings []Finding

	// NSAllowsArbitraryLoads = true disables ATS entirely.
	if arbitrary, ok := ats["NSAllowsArbitraryLoads"]; ok {
		if b, ok := arbitrary.(bool); ok && b {
			findings = append(findings, Finding{
				ID:         "ios.ats_arbitrary_loads",
				Category:   "cleartext",
				Severity:   SeverityWarn,
				Confidence: ConfidenceHigh,
				Message:    "NSAllowsArbitraryLoads is true — App Transport Security is disabled, cleartext HTTP allowed",
				Evidence: []Evidence{{
					ArchivePath: "Info.plist",
					Field:       "NSAppTransportSecurity.NSAllowsArbitraryLoads",
				}},
				Fingerprint: fingerprint("ios", "ats_arbitrary_loads"),
			})
		}
	}

	// Check exception domains for insecure settings.
	if domains, ok := ats["NSExceptionDomains"].(map[string]any); ok {
		for domain, config := range domains {
			domainCfg, ok := config.(map[string]any)
			if !ok {
				continue
			}
			// NSExceptionAllowsInsecureHTTPLoads = true
			if v, ok := domainCfg["NSExceptionAllowsInsecureHTTPLoads"]; ok {
				if b, ok := v.(bool); ok && b {
					findings = append(findings, Finding{
						ID:         fmt.Sprintf("ios.ats_insecure_domain.%s", sanitizeFindingID(domain)),
						Category:   "cleartext",
						Severity:   SeverityWarn,
						Confidence: ConfidenceHigh,
						Message:    fmt.Sprintf("ATS exception allows insecure HTTP for domain: %s", domain),
						Evidence: []Evidence{{
							ArchivePath:       "Info.plist",
							Field:             "NSExceptionDomains." + domain + ".NSExceptionAllowsInsecureHTTPLoads",
							MatchedTextMasked: domain,
						}},
						Fingerprint: fingerprint("ios", "ats_insecure", domain),
					})
				}
			}
			// NSTemporaryExceptionAllowsInsecureHTTPLoads (legacy key)
			if v, ok := domainCfg["NSTemporaryExceptionAllowsInsecureHTTPLoads"]; ok {
				if b, ok := v.(bool); ok && b {
					findings = append(findings, Finding{
						ID:         fmt.Sprintf("ios.ats_insecure_domain.%s", sanitizeFindingID(domain)),
						Category:   "cleartext",
						Severity:   SeverityWarn,
						Confidence: ConfidenceHigh,
						Message:    fmt.Sprintf("ATS temporary exception allows insecure HTTP for domain: %s", domain),
						Evidence: []Evidence{{
							ArchivePath:       "Info.plist",
							Field:             "NSExceptionDomains." + domain + ".NSTemporaryExceptionAllowsInsecureHTTPLoads",
							MatchedTextMasked: domain,
						}},
						Fingerprint: fingerprint("ios", "ats_insecure", domain),
					})
				}
			}
		}
	}

	return findings
}
