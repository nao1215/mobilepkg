package mobilepkg

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nao1215/mobilepkg/internal/secrets"
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
		result.secretCandidates = append(result.secretCandidates, scanSecretsInMap(ar.RawManifest, categoryManifest)...)
	}
	if ir, ok := asIOS(rpt); ok {
		if ir.InfoPlist != nil {
			result.secretCandidates = append(result.secretCandidates, scanSecretsInMap(ir.InfoPlist, "info_plist")...)
		}
		if ir.Entitlements != nil {
			result.secretCandidates = append(result.secretCandidates, scanSecretsInMap(ir.Entitlements, categoryEntitlement)...)
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
			Category:   categoryManifest,
			Severity:   SeverityError,
			Confidence: ConfidenceHigh,
			Message:    "application is debuggable — allows arbitrary code execution via adb on any device",
			Evidence: []Evidence{{
				ArchivePath: pathAndroidManifest,
				Field:       "application[@debuggable]",
			}},
			Fingerprint: fingerprint(categoryManifest, "debuggable"),
		})
	}

	if r.AllowBackup {
		findings = append(findings, Finding{
			ID:         "manifest.allow_backup",
			Category:   categoryManifest,
			Severity:   SeverityWarn,
			Confidence: ConfidenceHigh,
			Message:    "application allows backup — app data can be extracted via adb backup",
			Evidence: []Evidence{{
				ArchivePath: pathAndroidManifest,
				Field:       "application[@allowBackup]",
			}},
			Fingerprint: fingerprint(categoryManifest, "allowBackup"),
		})
	}

	if r.UsesCleartextTraffic {
		findings = append(findings, Finding{
			ID:         "manifest.cleartext_traffic",
			Category:   categoryManifest,
			Severity:   SeverityWarn,
			Confidence: ConfidenceHigh,
			Message:    "application permits cleartext (HTTP) traffic — network communication may be intercepted",
			Evidence: []Evidence{{
				ArchivePath: pathAndroidManifest,
				Field:       "application[@usesCleartextTraffic]",
			}},
			Fingerprint: fingerprint(categoryManifest, "usesCleartextTraffic"),
		})
	}

	if r.TestOnly {
		findings = append(findings, Finding{
			ID:         "manifest.test_only",
			Category:   categoryManifest,
			Severity:   SeverityError,
			Confidence: ConfidenceHigh,
			Message:    "application is testOnly — can only be installed via adb, not suitable for production",
			Evidence: []Evidence{{
				ArchivePath: pathAndroidManifest,
				Field:       "application[@testOnly]",
			}},
			Fingerprint: fingerprint(categoryManifest, "testOnly"),
		})
	}

	if r.ProfileableByShell {
		findings = append(findings, Finding{
			ID:         "manifest.profileable_by_shell",
			Category:   categoryManifest,
			Severity:   SeverityWarn,
			Confidence: ConfidenceHigh,
			Message:    "application is profileable from shell — may leak performance data in production",
			Evidence: []Evidence{{
				ArchivePath: pathAndroidManifest,
				Field:       "application[@profileableByShell]",
			}},
			Fingerprint: fingerprint(categoryManifest, "profileableByShell"),
		})
	}

	return findings
}

// componentRiskResult holds the assessed risk for an exported component.
type componentRiskResult struct {
	severity  Severity
	browsable bool
	protected bool
}

// assessComponentRisk determines the risk level of an exported component.
func assessComponentRisk(ec ExportedComponent) componentRiskResult {
	hasProtection := ec.Permission != "" || ec.ReadPermission != "" || ec.WritePermission != ""
	isBrowsable := componentIsBrowsable(ec)
	isProvider := ec.Kind == "provider"

	severity := SeverityInfo
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

	return componentRiskResult{
		severity:  severity,
		browsable: isBrowsable,
		protected: hasProtection,
	}
}

func analyzeExportedComponents(components []ExportedComponent) []Finding {
	var findings []Finding
	for _, ec := range components {
		if !ec.Exported {
			continue
		}

		risk := assessComponentRisk(ec)

		msg := fmt.Sprintf("exported %s: %s", ec.Kind, ec.Name)
		if ec.Permission != "" {
			msg += fmt.Sprintf(" (requires %s)", ec.Permission)
		} else if !risk.protected {
			msg += " (no permission required)"
		}
		if risk.browsable {
			msg += " [browsable]"
		}
		if ec.Authorities != "" {
			msg += fmt.Sprintf(" [authorities: %s]", ec.Authorities)
		}
		if ec.Kind == "provider" && ec.GrantURIPermissions {
			msg += " [grantUriPermissions]"
		}

		findings = append(findings, Finding{
			ID:         fmt.Sprintf("exported.%s.%s", ec.Kind, sanitizeFindingID(ec.Name)),
			Category:   "exported_component",
			Severity:   risk.severity,
			Confidence: ConfidenceHigh,
			Message:    msg,
			Evidence: []Evidence{{
				ArchivePath:       pathAndroidManifest,
				Field:             fmt.Sprintf("%s[@name]", ec.Kind),
				MatchedTextMasked: ec.Name,
			}},
			Fingerprint: fingerprint("exported", ec.Kind, ec.Name,
				ec.Permission, ec.ReadPermission, ec.WritePermission,
				ec.Authorities,
				fmt.Sprintf("%v", risk.browsable),
				fmt.Sprintf("%v", ec.GrantURIPermissions)),
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

// signingFinding builds a Finding with the "signing" category.
func signingFinding(id string, sev Severity, conf Confidence, msg, field, masked string, fpParts ...string) Finding {
	return Finding{
		ID:          id,
		Category:    "signing",
		Severity:    sev,
		Confidence:  conf,
		Message:     msg,
		Evidence:    []Evidence{{Field: field, MatchedTextMasked: masked}},
		Fingerprint: fingerprint(fpParts...),
	}
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
		findings = append(findings, signingFinding(
			"signing.v1_only", SeverityWarn, ConfidenceHigh,
			"APK uses v1 (JAR) signing only — vulnerable to modification without invalidating signature",
			"signing.scheme", signing.Scheme,
			"signing.v1_only",
		))
	}

	for _, cert := range signing.Certificates {
		// Detect debug/self-signed certificates.
		if isDebugCert(cert) {
			findings = append(findings, signingFinding(
				"signing.debug_cert", SeverityError, ConfidenceHigh,
				fmt.Sprintf("signed with debug certificate (subject: %s) — not suitable for production", cert.Subject),
				"certificate.subject", cert.Subject,
				"signing.debug", cert.SHA256Fingerprint,
			))
		}

		// Detect self-signed test certificates (not debug but still self-signed).
		if cert.SelfSigned && !isDebugCert(cert) {
			findings = append(findings, signingFinding(
				"signing.self_signed_test_cert", SeverityWarn, ConfidenceMedium,
				fmt.Sprintf("self-signed certificate (subject: %s) — may indicate a test build", cert.Subject),
				"certificate.subject", cert.Subject,
				"signing.self_signed", cert.SHA256Fingerprint,
			))
		}

		// Detect weak signature digest algorithms.
		if isWeakDigest(cert.SignatureAlgorithm) {
			findings = append(findings, signingFinding(
				"signing.weak_digest", SeverityWarn, ConfidenceHigh,
				fmt.Sprintf("certificate uses weak signature algorithm: %s", cert.SignatureAlgorithm),
				"certificate.signature_algorithm", cert.SignatureAlgorithm,
				"signing.weak_digest", cert.SHA256Fingerprint,
			))
		}

		// Detect weak key sizes.
		if isWeakKeySize(cert.PublicKeyAlgorithm, cert.KeySize) {
			findings = append(findings, signingFinding(
				"signing.weak_key_size", SeverityWarn, ConfidenceHigh,
				fmt.Sprintf("certificate uses weak key: %s %d-bit", cert.PublicKeyAlgorithm, cert.KeySize),
				"certificate.key_size", fmt.Sprintf("%s %d", cert.PublicKeyAlgorithm, cert.KeySize),
				"signing.weak_key", cert.SHA256Fingerprint,
			))
		}

		// Detect expired certificates.
		if cert.NotAfter != "" {
			expiry, err := time.Parse(time.RFC3339, cert.NotAfter)
			if err == nil && now.After(expiry) {
				findings = append(findings, signingFinding(
					fmt.Sprintf("signing.expired.%s", sanitizeFindingID(cert.SHA256Fingerprint)),
					SeverityWarn, ConfidenceHigh,
					fmt.Sprintf("signing certificate expired: %s (subject: %s)", cert.NotAfter, cert.Subject),
					"certificate.not_after", cert.NotAfter,
					"signing.expired", cert.SHA256Fingerprint,
				))
			}
		}
	}

	// iOS provisioning profile expiration.
	if signing.ProvisioningExpiresAt != "" {
		expiry, err := time.Parse(time.RFC3339, signing.ProvisioningExpiresAt)
		if err == nil && now.After(expiry) {
			findings = append(findings, signingFinding(
				"signing.provisioning_expired", SeverityWarn, ConfidenceHigh,
				fmt.Sprintf("iOS provisioning profile expired: %s", signing.ProvisioningExpiresAt),
				"provisioning.expires_at", signing.ProvisioningExpiresAt,
				"signing.provisioning_expired",
			))
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
				ArchivePath:       pathAndroidManifest,
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
	if v, ok := ir.Entitlements[entitlementGetTaskAllow]; ok {
		if b, ok := v.(bool); ok && b {
			findings = append(findings, Finding{
				ID:         "ios.get_task_allow",
				Category:   categoryEntitlement,
				Severity:   SeverityError,
				Confidence: ConfidenceHigh,
				Message:    "get-task-allow is true — this is a debug build, debugger can attach to the process",
				Evidence: []Evidence{{
					ArchivePath: "embedded.mobileprovision",
					Field:       entitlementGetTaskAllow,
				}},
				Fingerprint: fingerprint("ios", entitlementGetTaskAllow),
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
		if p.Source == categoryEntitlement && p.RawName == entitlementGetTaskAllow {
			findings = append(findings, Finding{
				ID:         "ios.get_task_allow",
				Category:   categoryEntitlement,
				Severity:   SeverityError,
				Confidence: ConfidenceHigh,
				Message:    "get-task-allow entitlement present — likely a debug build",
				Evidence: []Evidence{{
					ArchivePath: "embedded.mobileprovision",
					Field:       entitlementGetTaskAllow,
				}},
				Fingerprint: fingerprint("ios", entitlementGetTaskAllow),
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
						Source:     categoryEntitlement,
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

func scanSecretsInStrings(kvPairs map[string]string, source string) []SecretCandidate {
	var candidates []SecretCandidate
	for key, value := range kvPairs {
		for _, sp := range secrets.Patterns {
			if sp.Re.MatchString(value) || sp.Re.MatchString(key+"="+value) {
				candidates = append(candidates, SecretCandidate{
					Kind:        sp.Kind,
					MaskedValue: maskSecret(value),
					Source:      source,
					Confidence:  Confidence(sp.Confidence),
				})
				break
			}
		}
	}
	return candidates
}

func scanSecretsInMap(m map[string]any, source string) []SecretCandidate {
	flat := make(map[string]string)
	walkStringLeaves(m, "", func(key, value string) {
		flat[key] = value
	})
	return scanSecretsInStrings(flat, source)
}

// walkStringLeaves visits every string-typed leaf in a nested structure
// of map[string]any, []any, and []string. The callback receives the
// dotted key path and the string value.
func walkStringLeaves(m map[string]any, prefix string, fn func(key, value string)) {
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		visitValue(key, v, fn)
	}
}

func visitValue(key string, v any, fn func(key, value string)) {
	switch val := v.(type) {
	case string:
		fn(key, val)
	case map[string]any:
		walkStringLeaves(val, key, fn)
	case []any:
		for i, item := range val {
			visitValue(fmt.Sprintf("%s[%d]", key, i), item, fn)
		}
	case []string:
		for i, elem := range val {
			fn(fmt.Sprintf("%s[%d]", key, i), elem)
		}
	}
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
			Category:   categoryCleartext,
			Severity:   SeverityWarn,
			Confidence: ConfidenceHigh,
			Message:    "network security config base-config permits cleartext traffic",
			Evidence: []Evidence{{
				ArchivePath: pathNetworkSecurityConfig,
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
			Category:   categoryCleartext,
			Severity:   SeverityWarn,
			Confidence: ConfidenceHigh,
			Message:    "network security config contains debug-overrides — may weaken TLS validation in debug builds",
			Evidence: []Evidence{{
				ArchivePath: pathNetworkSecurityConfig,
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
			Category:   categoryCleartext,
			Severity:   SeverityWarn,
			Confidence: ConfidenceHigh,
			Message:    fmt.Sprintf("network security config permits cleartext traffic for: %s", domains),
			Evidence: []Evidence{{
				ArchivePath:       pathNetworkSecurityConfig,
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
				Category:   categoryCleartext,
				Severity:   SeverityWarn,
				Confidence: ConfidenceHigh,
				Message:    "NSAllowsArbitraryLoads is true — App Transport Security is disabled, cleartext HTTP allowed",
				Evidence: []Evidence{{
					ArchivePath: pathInfoPlist,
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
						Category:   categoryCleartext,
						Severity:   SeverityWarn,
						Confidence: ConfidenceHigh,
						Message:    fmt.Sprintf("ATS exception allows insecure HTTP for domain: %s", domain),
						Evidence: []Evidence{{
							ArchivePath:       pathInfoPlist,
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
						Category:   categoryCleartext,
						Severity:   SeverityWarn,
						Confidence: ConfidenceHigh,
						Message:    fmt.Sprintf("ATS temporary exception allows insecure HTTP for domain: %s", domain),
						Evidence: []Evidence{{
							ArchivePath:       pathInfoPlist,
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
