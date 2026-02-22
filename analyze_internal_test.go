package mobilepkg

import (
	"strings"
	"testing"
	"time"
)

func TestAnalyzeReport_Android(t *testing.T) {
	t.Parallel()

	rpt := report{
		Platform:             PlatformAndroid,
		Version:              Version{Marketing: "2.0.0", Build: "2"},
		Debuggable:           true,
		AllowBackup:          true,
		UsesCleartextTraffic: true,
		Permissions: []Permission{
			{RawName: "android.permission.CAMERA", Source: "manifest"},
		},
		ExportedComponents: []ExportedComponent{
			{
				Kind:       "activity",
				Name:       "com.example.DeepLinkActivity",
				Exported:   true,
				Permission: "com.example.PERM",
				IntentFilters: []IntentFilter{{
					Actions: []string{"android.intent.action.VIEW"},
					Data: []DataSpec{{
						Scheme: "https",
						Host:   "api.example.com",
						Path:   "/login",
					}},
				}},
			},
			{
				Kind:        "provider",
				Name:        "com.example.Provider",
				Exported:    true,
				Authorities: "com.example.provider",
			},
		},
		Signing: &SigningInfo{
			Scheme: "v1",
			Certificates: []CertSummary{{
				Subject:           "Android Debug",
				Issuer:            "Android Debug",
				NotAfter:          time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC).Format(time.RFC3339),
				SHA256Fingerprint: "deadbeef",
			}},
		},
		PlatformData: &androidReport{
			RawManifest: map[string]any{
				"api_key": "api_key=abcdefghijklmnopqrstuvwxyz123456",
				"nested": map[string]any{
					"token": "Bearer abcdefghijklmnopqrstuvwxyz1234567890",
				},
			},
		},
	}

	baseline := report{
		Platform: PlatformAndroid,
		Version:  Version{Marketing: "1.0.0", Build: "1"},
	}

	got := analyzeReport(rpt, analyzeOptions{baseline: &baseline})

	if got.diff == nil || !got.diff.VersionChanged {
		t.Fatalf("diff = %#v, want version change", got.diff)
	}
	if len(got.report.NetworkEndpoints) != 1 {
		t.Fatalf("NetworkEndpoints = %#v, want one deep link", got.report.NetworkEndpoints)
	}
	if got.report.NetworkEndpoints[0].Host != "api.example.com" {
		t.Fatalf("deep link host = %q, want %q", got.report.NetworkEndpoints[0].Host, "api.example.com")
	}
	if len(got.secretCandidates) == 0 {
		t.Fatal("secretCandidates should not be empty")
	}

	ids := map[string]bool{}
	for _, f := range got.findings {
		ids[f.ID] = true
	}
	for _, want := range []string{
		"manifest.debuggable",
		"manifest.allow_backup",
		"manifest.cleartext_traffic",
		"exported.activity.com.example.DeepLinkActivity",
		"exported.provider.com.example.Provider",
		"signing.debug_cert",
		"perm.dangerous.android.permission.CAMERA",
	} {
		if !ids[want] {
			t.Fatalf("missing finding %q in %#v", want, got.findings)
		}
	}
}

func TestIOSHelpersAndEntitlements(t *testing.T) {
	t.Parallel()

	info := map[string]any{
		"NSAppTransportSecurity": map[string]any{
			"NSExceptionDomains": map[string]any{
				"api.example.com": map[string]any{},
			},
		},
		"CFBundleURLTypes": []any{
			map[string]any{
				"CFBundleURLSchemes": []any{"myapp"},
			},
		},
	}
	entitlements := map[string]any{
		"get-task-allow": true,
		"com.apple.developer.associated-domains": []any{
			"applinks:example.com",
			"webcredentials:login.example.com",
			"ignored",
		},
	}

	plistEndpoints := extractEndpointsFromPlist(info)
	if len(plistEndpoints) != 2 {
		t.Fatalf("extractEndpointsFromPlist = %#v, want 2 endpoints", plistEndpoints)
	}

	entitlementEndpoints := extractEndpointsFromEntitlements(entitlements)
	if len(entitlementEndpoints) != 2 {
		t.Fatalf("extractEndpointsFromEntitlements = %#v, want 2 endpoints", entitlementEndpoints)
	}

	findings := analyzeIOSEntitlements(report{
		Platform: PlatformIOS,
		PlatformData: &iosReport{
			InfoPlist:    info,
			Entitlements: entitlements,
		},
	})
	if len(findings) != 1 || findings[0].ID != "ios.get_task_allow" {
		t.Fatalf("analyzeIOSEntitlements = %#v", findings)
	}

	permissionFindings := analyzeIOSEntitlementsFromPermissions(report{
		Permissions: []Permission{
			{RawName: "get-task-allow", Source: "entitlement"},
		},
	})
	if len(permissionFindings) != 1 || permissionFindings[0].ID != "ios.get_task_allow" {
		t.Fatalf("analyzeIOSEntitlementsFromPermissions = %#v", permissionFindings)
	}
}

func TestScanSecretsMaskingAndFlatten(t *testing.T) {
	t.Parallel()

	flat := flattenMap(map[string]any{
		"outer": map[string]any{
			"inner": "api_key=abcdefghijklmnopqrstuvwxyz123456",
		},
		"ignored": 123,
	}, "")
	if flat["outer.inner"] == "" {
		t.Fatalf("flattenMap = %#v, want nested key", flat)
	}

	candidates := scanSecretsInMap(map[string]any{
		"token": "ghp_abcdefghijklmnopqrstuvwxyz1234567890AB",
	}, "info_plist")
	if len(candidates) != 1 {
		t.Fatalf("scanSecretsInMap = %#v, want 1 candidate", candidates)
	}
	if candidates[0].MaskedValue == "" || candidates[0].SHA256 == "" {
		t.Fatalf("candidate = %#v, want masked value and hash", candidates[0])
	}

	if got := maskSecret("abcd"); got != "****" {
		t.Fatalf("maskSecret(short) = %q, want %q", got, "****")
	}
	if got := maskSecret("abcdefghijklmnopqrstuvwxyz"); !strings.HasPrefix(got, "abcdef") || !strings.Contains(got, "*") {
		t.Fatalf("maskSecret(long) = %q, want prefix preserved and masked tail", got)
	}
}

func TestSortReportAndBuildSigningTable(t *testing.T) {
	t.Parallel()

	rpt := report{
		Permissions: []Permission{
			{RawName: "b.permission"},
			{RawName: "a.permission"},
		},
		ExportedComponents: []ExportedComponent{
			{Kind: "service", Name: "B"},
			{Kind: "activity", Name: "A"},
		},
		NetworkEndpoints: []NetworkEndpoint{
			{Host: "z.example.com"},
			{Host: "a.example.com"},
		},
		Diagnostics: []Diagnostic{
			{Code: "z.warn"},
			{Code: "a.warn"},
		},
	}
	sortReport(&rpt)

	if rpt.Permissions[0].RawName != "a.permission" {
		t.Fatalf("Permissions not sorted: %#v", rpt.Permissions)
	}
	if rpt.ExportedComponents[0].Kind != "activity" {
		t.Fatalf("ExportedComponents not sorted: %#v", rpt.ExportedComponents)
	}
	if rpt.NetworkEndpoints[0].Host != "a.example.com" {
		t.Fatalf("NetworkEndpoints not sorted: %#v", rpt.NetworkEndpoints)
	}
	if rpt.Diagnostics[0].Code != "a.warn" {
		t.Fatalf("Diagnostics not sorted: %#v", rpt.Diagnostics)
	}

	table := buildSigningTable(&SigningInfo{
		Certificates: []CertSummary{{
			Subject:           "Developer",
			Issuer:            "CA",
			NotAfter:          "2030-01-02T03:04:05Z",
			SHA256Fingerprint: "1234567890abcdef1234567890abcdef",
		}},
	})
	if !strings.Contains(table, "Developer") || !strings.Contains(table, "1234567890abcdef...") {
		t.Fatalf("buildSigningTable = %q", table)
	}
}
