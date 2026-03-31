package mobilepkg

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Secret detection tests ---

func TestSecretID_NoRawPrefix(t *testing.T) {
	t.Parallel()

	// Ensure that secret finding IDs from DEX scanning do not contain
	// raw secret prefixes — they should use hash-based IDs.
	rpt := report{
		Platform: PlatformAndroid,
		PlatformData: &androidReport{
			RawManifest: map[string]any{
				"key": "AKIAIOSFODNN7EXAMPLE",
			},
		},
	}
	result := analyzeReport(rpt, analyzeOptions{})
	for _, f := range result.findings {
		if f.Category == "dex_secret" {
			assert.NotContains(t, f.ID, "AKIA",
				"finding ID should not contain raw secret prefix")
		}
	}
}

func TestFlattenMap_ArraysTraversed(t *testing.T) {
	t.Parallel()

	m := map[string]any{
		"items": []any{
			"ghp_abcdefghijklmnopqrstuvwxyz1234567890AB",
			map[string]any{
				"nested_token": "Bearer abcdefghijklmnopqrstuvwxyz1234567890",
			},
		},
	}

	flat := flattenMap(m, "")
	assert.Contains(t, flat, "items[0]")
	assert.Contains(t, flat, "items[1].nested_token")
}

func TestFlattenMap_TypedStringSlice(t *testing.T) {
	t.Parallel()

	// Android raw manifest stores permission arrays as []string, not []any.
	m := map[string]any{
		"permissions": []string{
			"android.permission.INTERNET",
			"android.permission.CAMERA",
		},
	}

	flat := flattenMap(m, "")
	assert.Contains(t, flat, "permissions[0]")
	assert.Equal(t, "android.permission.INTERNET", flat["permissions[0]"])
	assert.Contains(t, flat, "permissions[1]")
	assert.Equal(t, "android.permission.CAMERA", flat["permissions[1]"])
}

func TestScanSecretsInMap_PlistArraySecrets(t *testing.T) {
	t.Parallel()

	m := map[string]any{
		"urls": []any{
			"https://normal.example.com",
			"ghp_abcdefghijklmnopqrstuvwxyz1234567890AB",
		},
	}

	candidates := scanSecretsInMap(m, "info_plist")
	require.NotEmpty(t, candidates, "should detect GitHub token in array")
	assert.Equal(t, "github_token", candidates[0].Kind)
	assert.NotContains(t, candidates[0].MaskedValue, "ghp_abcdefghijklmnopqrstuvwxyz",
		"masked value should not expose full token")
}

func TestSecretPatterns_GCPKey(t *testing.T) {
	t.Parallel()

	// GCP API key pattern should be detected in manifest scanning.
	gcpKey := "AI" + "zaSyA1234567890abcdefghijklmnopqrstuv"
	m := map[string]any{"api_key": gcpKey}
	candidates := scanSecretsInMap(m, "manifest")
	require.NotEmpty(t, candidates)
	assert.Equal(t, "gcp_api_key", candidates[0].Kind)
}

func TestSecretPatterns_PrivateKey(t *testing.T) {
	t.Parallel()

	m := map[string]any{"cert": "-----BEGIN RSA PRIVATE KEY-----"}
	candidates := scanSecretsInMap(m, "manifest")
	require.NotEmpty(t, candidates)
	assert.Equal(t, "private_key", candidates[0].Kind)
}

func TestSecretPatterns_FirebaseURL(t *testing.T) {
	t.Parallel()

	m := map[string]any{"db": "https://my-app-12345.firebaseio.com"}
	candidates := scanSecretsInMap(m, "manifest")
	require.NotEmpty(t, candidates)
	assert.Equal(t, "firebase_url", candidates[0].Kind)
}

// --- NSC analysis tests ---

func TestAnalyzeNSCPolicy_BaseCleartext(t *testing.T) {
	t.Parallel()

	rpt := report{
		Platform: PlatformAndroid,
		NSCPolicy: &NetworkSecurityPolicy{
			CleartextPermitted: true,
		},
	}

	findings := analyzeNSCPolicy(rpt)
	require.Len(t, findings, 1)
	assert.Equal(t, "nsc.base_config_cleartext", findings[0].ID)
}

func TestAnalyzeNSCPolicy_DomainCleartext(t *testing.T) {
	t.Parallel()

	rpt := report{
		Platform: PlatformAndroid,
		NSCPolicy: &NetworkSecurityPolicy{
			DomainConfigs: []DomainConfig{
				{
					Domains:            []string{"api.example.com"},
					CleartextPermitted: true,
				},
			},
		},
	}

	findings := analyzeNSCPolicy(rpt)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].ID, "nsc.domain_cleartext")
	assert.Contains(t, findings[0].Message, "api.example.com")
}

func TestAnalyzeNSCPolicy_NestedDomainConfig(t *testing.T) {
	t.Parallel()

	rpt := report{
		Platform: PlatformAndroid,
		NSCPolicy: &NetworkSecurityPolicy{
			DomainConfigs: []DomainConfig{
				{
					Domains:            []string{"outer.example.com"},
					CleartextPermitted: false,
					NestedConfigs: []DomainConfig{
						{
							Domains:            []string{"inner.example.com"},
							CleartextPermitted: true,
						},
					},
				},
			},
		},
	}

	findings := analyzeNSCPolicy(rpt)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Message, "inner.example.com")
}

func TestAnalyzeNSCPolicy_DebugOverrides(t *testing.T) {
	t.Parallel()

	rpt := report{
		Platform: PlatformAndroid,
		NSCPolicy: &NetworkSecurityPolicy{
			HasDebugOverrides: true,
		},
	}

	findings := analyzeNSCPolicy(rpt)
	require.Len(t, findings, 1)
	assert.Equal(t, "nsc.debug_overrides", findings[0].ID)
}

// --- iOS ATS tests ---

func TestAnalyzeIOSATS_ArbitraryLoads(t *testing.T) {
	t.Parallel()

	rpt := report{
		Platform: PlatformIOS,
		PlatformData: &iosReport{
			InfoPlist: map[string]any{
				"NSAppTransportSecurity": map[string]any{
					"NSAllowsArbitraryLoads": true,
				},
			},
		},
	}

	findings := analyzeIOSATS(rpt)
	require.Len(t, findings, 1)
	assert.Equal(t, "ios.ats_arbitrary_loads", findings[0].ID)
	assert.Equal(t, SeverityWarn, findings[0].Severity)
}

func TestAnalyzeIOSATS_InsecureExceptionDomain(t *testing.T) {
	t.Parallel()

	rpt := report{
		Platform: PlatformIOS,
		PlatformData: &iosReport{
			InfoPlist: map[string]any{
				"NSAppTransportSecurity": map[string]any{
					"NSExceptionDomains": map[string]any{
						"insecure.example.com": map[string]any{
							"NSExceptionAllowsInsecureHTTPLoads": true,
						},
					},
				},
			},
		},
	}

	findings := analyzeIOSATS(rpt)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].ID, "ios.ats_insecure_domain")
	assert.Contains(t, findings[0].Message, "insecure.example.com")
}

func TestAnalyzeIOSATS_SecureDomainNoFinding(t *testing.T) {
	t.Parallel()

	rpt := report{
		Platform: PlatformIOS,
		PlatformData: &iosReport{
			InfoPlist: map[string]any{
				"NSAppTransportSecurity": map[string]any{
					"NSAllowsArbitraryLoads": false,
					"NSExceptionDomains": map[string]any{
						"secure.example.com": map[string]any{
							"NSExceptionAllowsInsecureHTTPLoads": false,
						},
					},
				},
			},
		},
	}

	findings := analyzeIOSATS(rpt)
	assert.Empty(t, findings)
}

// --- Debug flag tests ---

func TestAnalyzeManifest_TestOnly(t *testing.T) {
	t.Parallel()

	rpt := report{
		Platform: PlatformAndroid,
		TestOnly: true,
	}
	findings := analyzeManifestSecurity(rpt)

	ids := map[string]bool{}
	for _, f := range findings {
		ids[f.ID] = true
	}
	assert.True(t, ids["manifest.test_only"])
}

func TestAnalyzeManifest_ProfileableByShell(t *testing.T) {
	t.Parallel()

	rpt := report{
		Platform:           PlatformAndroid,
		ProfileableByShell: true,
	}
	findings := analyzeManifestSecurity(rpt)

	ids := map[string]bool{}
	for _, f := range findings {
		ids[f.ID] = true
	}
	assert.True(t, ids["manifest.profileable_by_shell"])
}

// --- Weak signing tests ---

func TestAnalyzeSigningInfo_V1Only(t *testing.T) {
	t.Parallel()

	signing := &SigningInfo{
		Scheme: "v1",
		Certificates: []CertSummary{{
			Subject:            "Test",
			Issuer:             "CA",
			SignatureAlgorithm: "SHA256-RSA",
			PublicKeyAlgorithm: "RSA",
			KeySize:            2048,
		}},
	}

	findings := analyzeSigningInfo(signing)
	ids := map[string]bool{}
	for _, f := range findings {
		ids[f.ID] = true
	}
	assert.True(t, ids["signing.v1_only"], "should detect v1-only signing")
}

func TestAnalyzeSigningInfo_V2NotFlagged(t *testing.T) {
	t.Parallel()

	signing := &SigningInfo{
		Scheme: "v1+v2",
		Certificates: []CertSummary{{
			Subject:            "Test",
			Issuer:             "CA",
			SignatureAlgorithm: "SHA256-RSA",
			PublicKeyAlgorithm: "RSA",
			KeySize:            2048,
		}},
	}

	findings := analyzeSigningInfo(signing)
	for _, f := range findings {
		assert.NotEqual(t, "signing.v1_only", f.ID, "v1+v2 should not trigger v1_only")
	}
}

func TestAnalyzeSigningInfo_WeakDigest(t *testing.T) {
	t.Parallel()

	signing := &SigningInfo{
		Scheme: "v2",
		Certificates: []CertSummary{{
			Subject:            "Test",
			Issuer:             "CA",
			SignatureAlgorithm: "SHA1-RSA",
			PublicKeyAlgorithm: "RSA",
			KeySize:            2048,
		}},
	}

	findings := analyzeSigningInfo(signing)
	ids := map[string]bool{}
	for _, f := range findings {
		ids[f.ID] = true
	}
	assert.True(t, ids["signing.weak_digest"], "should detect SHA1 digest")
}

func TestAnalyzeSigningInfo_WeakKeySize(t *testing.T) {
	t.Parallel()

	signing := &SigningInfo{
		Scheme: "v2",
		Certificates: []CertSummary{{
			Subject:            "Test",
			Issuer:             "CA",
			SignatureAlgorithm: "SHA256-RSA",
			PublicKeyAlgorithm: "RSA",
			KeySize:            1024,
		}},
	}

	findings := analyzeSigningInfo(signing)
	ids := map[string]bool{}
	for _, f := range findings {
		ids[f.ID] = true
	}
	assert.True(t, ids["signing.weak_key_size"], "should detect 1024-bit RSA")
}

func TestAnalyzeSigningInfo_SelfSignedTestCert(t *testing.T) {
	t.Parallel()

	signing := &SigningInfo{
		Scheme: "v2",
		Certificates: []CertSummary{{
			Subject:            "MyCompany",
			Issuer:             "MyCompany",
			SignatureAlgorithm: "SHA256-RSA",
			PublicKeyAlgorithm: "RSA",
			KeySize:            2048,
			SelfSigned:         true,
		}},
	}

	findings := analyzeSigningInfo(signing)
	ids := map[string]bool{}
	for _, f := range findings {
		ids[f.ID] = true
	}
	assert.True(t, ids["signing.self_signed_test_cert"], "should detect self-signed cert")
	assert.False(t, ids["signing.debug_cert"], "non-debug self-signed should not trigger debug_cert")
}

func TestAnalyzeSigningInfo_ExpiredCert(t *testing.T) {
	t.Parallel()

	signing := &SigningInfo{
		Scheme: "v2",
		Certificates: []CertSummary{{
			Subject:           "Test",
			Issuer:            "CA",
			NotAfter:          time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
			SHA256Fingerprint: "deadbeef",
		}},
	}

	findings := analyzeSigningInfo(signing)
	hasExpired := false
	for _, f := range findings {
		if strings.HasPrefix(f.ID, "signing.expired") {
			hasExpired = true
		}
	}
	assert.True(t, hasExpired)
}

func TestAnalyzeSigningInfo_ProvisioningExpired(t *testing.T) {
	t.Parallel()

	signing := &SigningInfo{
		Scheme:                "apple",
		ProvisioningExpiresAt: time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
	}

	findings := analyzeSigningInfo(signing)
	ids := map[string]bool{}
	for _, f := range findings {
		ids[f.ID] = true
	}
	assert.True(t, ids["signing.provisioning_expired"],
		"should detect expired provisioning profile")
}

func TestAnalyzeSigningInfo_ProvisioningNotExpired(t *testing.T) {
	t.Parallel()

	signing := &SigningInfo{
		Scheme:                "apple",
		ProvisioningExpiresAt: time.Date(2099, 6, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
	}

	findings := analyzeSigningInfo(signing)
	for _, f := range findings {
		assert.NotEqual(t, "signing.provisioning_expired", f.ID)
	}
}

// --- Exported component priority tests ---

func TestAnalyzeExportedComponents_ProviderNoPermission(t *testing.T) {
	t.Parallel()

	components := []ExportedComponent{
		{
			Kind:        "provider",
			Name:        "com.example.DataProvider",
			Exported:    true,
			Authorities: "com.example.data",
			// No permission set
		},
	}

	findings := analyzeExportedComponents(components)
	require.Len(t, findings, 1)
	assert.Equal(t, SeverityError, findings[0].Severity,
		"exported provider without permission should be error severity")
	assert.Contains(t, findings[0].Message, "no permission required")
	assert.Contains(t, findings[0].Message, "[authorities: com.example.data]")
}

func TestAnalyzeExportedComponents_ProviderWithPermission(t *testing.T) {
	t.Parallel()

	components := []ExportedComponent{
		{
			Kind:       "provider",
			Name:       "com.example.DataProvider",
			Exported:   true,
			Permission: "com.example.READ",
		},
	}

	findings := analyzeExportedComponents(components)
	require.Len(t, findings, 1)
	assert.Equal(t, SeverityWarn, findings[0].Severity,
		"exported provider with permission should be warn severity")
}

func TestAnalyzeExportedComponents_BrowsableActivity(t *testing.T) {
	t.Parallel()

	components := []ExportedComponent{
		{
			Kind:     "activity",
			Name:     "com.example.DeepLinkActivity",
			Exported: true,
			IntentFilters: []IntentFilter{{
				Actions:    []string{"android.intent.action.VIEW"},
				Categories: []string{"android.intent.category.DEFAULT", "android.intent.category.BROWSABLE"},
				Data:       []DataSpec{{Scheme: "https", Host: "example.com"}},
			}},
		},
	}

	findings := analyzeExportedComponents(components)
	require.Len(t, findings, 1)
	assert.Equal(t, SeverityWarn, findings[0].Severity,
		"browsable activity without permission should be warn")
	assert.Contains(t, findings[0].Message, "[browsable]")
}

func TestAnalyzeExportedComponents_ServiceNoPermission(t *testing.T) {
	t.Parallel()

	components := []ExportedComponent{
		{
			Kind:     "service",
			Name:     "com.example.MyService",
			Exported: true,
		},
	}

	findings := analyzeExportedComponents(components)
	require.Len(t, findings, 1)
	assert.Equal(t, SeverityWarn, findings[0].Severity,
		"exported service without permission should be warn")
}

func TestAnalyzeExportedComponents_ProviderGrantURIPermissions(t *testing.T) {
	t.Parallel()

	components := []ExportedComponent{
		{
			Kind:                "provider",
			Name:                "com.example.FileProvider",
			Exported:            true,
			GrantURIPermissions: true,
		},
	}

	findings := analyzeExportedComponents(components)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Message, "[grantUriPermissions]")
}

// --- Weak signing helper tests ---

func TestIsWeakDigest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		algo string
		weak bool
	}{
		{"SHA256-RSA", false},
		{"SHA384-RSA", false},
		{"SHA512-RSA", false},
		{"SHA1-RSA", true},
		{"MD5-RSA", true},
		{"MD2-RSA", true},
		{"SHA256WithRSAEncryption", false},
		{"SHA1WithRSAEncryption", true},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.algo, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.weak, isWeakDigest(tt.algo))
		})
	}
}

func TestIsWeakKeySize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		algo string
		bits int
		weak bool
	}{
		{"RSA", 4096, false},
		{"RSA", 2048, false},
		{"RSA", 1024, true},
		{"RSA", 512, true},
		{"ECDSA", 256, false},
		{"ECDSA", 384, false},
		{"ECDSA", 192, true},
		{"DSA", 2048, false},
		{"DSA", 1024, true},
		{"Ed25519", 256, false},
		{"RSA", 0, false}, // unknown size
	}

	for _, tt := range tests {
		t.Run(tt.algo+string(rune('0'+tt.bits%10)), func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.weak, isWeakKeySize(tt.algo, tt.bits))
		})
	}
}
