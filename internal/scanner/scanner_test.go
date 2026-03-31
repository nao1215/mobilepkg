package scanner

import (
	"testing"

	"github.com/nao1215/mobilepkg/internal/dex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTestDEXWithStrings creates a minimal DEX file containing the given strings.
func buildTestDEXWithStrings(t *testing.T, strings []string) *dex.File {
	t.Helper()
	data := buildMinDEX(t, strings)
	f, err := dex.Parse(data)
	require.NoError(t, err)
	return f
}

func TestScan_Empty(t *testing.T) {
	t.Parallel()

	ctx := &Context{}
	findings := Scan(ctx)
	assert.Empty(t, findings)
}

func TestScan_NoDexFiles(t *testing.T) {
	t.Parallel()

	ctx := &Context{
		DexFiles: nil,
	}
	findings := Scan(ctx)
	assert.Empty(t, findings)
}

func TestHardcodedSecrets_AWSKey(t *testing.T) {
	t.Parallel()

	df := buildTestDEXWithStrings(t, []string{
		"AKIAIOSFODNN7EXAMPLE",
		"normal string",
	})

	ctx := &Context{DexFiles: []*dex.File{df}}
	rule := &hardcodedSecretsRule{}
	findings := rule.Match(ctx)

	require.Len(t, findings, 1)
	assert.Equal(t, "dex_secret", findings[0].Category)
	assert.Equal(t, "error", findings[0].Severity)
	assert.Contains(t, findings[0].Message, "aws_key")
}

func TestHardcodedSecrets_GCPKey(t *testing.T) {
	t.Parallel()

	// Construct at runtime so secret scanners do not flag the test fixture itself.
	gcpKey := "AI" + "zaSyA1234567890abcdefghijklmnopqrstuv"

	df := buildTestDEXWithStrings(t, []string{
		gcpKey,
	})

	ctx := &Context{DexFiles: []*dex.File{df}}
	rule := &hardcodedSecretsRule{}
	findings := rule.Match(ctx)

	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Message, "gcp_api_key")
}

func TestHardcodedSecrets_NoFalsePositive(t *testing.T) {
	t.Parallel()

	df := buildTestDEXWithStrings(t, []string{
		"http://schemas.android.com/apk/res/android",
		"com.google.android.gms",
		"android.permission.INTERNET",
		"short",
	})

	ctx := &Context{DexFiles: []*dex.File{df}}
	rule := &hardcodedSecretsRule{}
	findings := rule.Match(ctx)

	assert.Empty(t, findings)
}

func TestCleartextTraffic_HTTPUrl(t *testing.T) {
	t.Parallel()

	df := buildTestDEXWithStrings(t, []string{
		"http://api.example.com/v1/data",
		"https://secure.example.com/api",
	})

	ctx := &Context{DexFiles: []*dex.File{df}}
	rule := &cleartextTrafficRule{}
	findings := rule.Match(ctx)

	require.Len(t, findings, 1)
	assert.Equal(t, "dex_cleartext", findings[0].Category)
	assert.Contains(t, findings[0].Message, "api.example.com")
}

func TestCleartextTraffic_LocalhostExcluded(t *testing.T) {
	t.Parallel()

	df := buildTestDEXWithStrings(t, []string{
		"http://localhost:8080/api",
		"http://127.0.0.1:3000/test",
		"http://10.0.2.2/debug",
	})

	ctx := &Context{DexFiles: []*dex.File{df}}
	rule := &cleartextTrafficRule{}
	findings := rule.Match(ctx)

	assert.Empty(t, findings)
}

func TestCleartextTraffic_SchemaExcluded(t *testing.T) {
	t.Parallel()

	df := buildTestDEXWithStrings(t, []string{
		"http://schemas.android.com/apk/res/android",
		"http://www.w3.org/2001/XMLSchema",
		"http://xmlpull.org/v1/doc/features.html",
	})

	ctx := &Context{DexFiles: []*dex.File{df}}
	rule := &cleartextTrafficRule{}
	findings := rule.Match(ctx)

	assert.Empty(t, findings)
}

func TestMergedStrings(t *testing.T) {
	t.Parallel()

	df1 := buildTestDEXWithStrings(t, []string{"hello", "world"})
	df2 := buildTestDEXWithStrings(t, []string{"world", "foo"})

	ctx := &Context{DexFiles: []*dex.File{df1, df2}}
	merged := ctx.MergedStrings()

	assert.Len(t, merged, 3) // "hello", "world", "foo" (deduplicated)
	assert.Contains(t, merged, "hello")
	assert.Contains(t, merged, "world")
	assert.Contains(t, merged, "foo")
}

func TestDefaultRules(t *testing.T) {
	t.Parallel()

	rules := DefaultRules()
	assert.Len(t, rules, 4)

	names := make([]string, len(rules))
	for i, r := range rules {
		names[i] = r.Name()
	}
	assert.Contains(t, names, "HardcodedSecrets")
	assert.Contains(t, names, "InsecureWebView")
	assert.Contains(t, names, "CleartextTraffic")
	assert.Contains(t, names, "DangerousAPIs")
}

func TestCleartextTraffic_ImplausibleHostExcluded(t *testing.T) {
	t.Parallel()

	df := buildTestDEXWithStrings(t, []string{
		"http://wifi-not-enabled",
		"http://www./something",
	})

	ctx := &Context{DexFiles: []*dex.File{df}}
	rule := &cleartextTrafficRule{}
	findings := rule.Match(ctx)

	assert.Empty(t, findings, "implausible hostnames should be excluded")
}

func TestCleartextTraffic_SingleLabelHostKept(t *testing.T) {
	t.Parallel()

	df := buildTestDEXWithStrings(t, []string{
		"http://intranet/admin",
		"http://metadata/latest",
	})

	ctx := &Context{DexFiles: []*dex.File{df}}
	rule := &cleartextTrafficRule{}
	findings := rule.Match(ctx)

	assert.Len(t, findings, 2, "single-label hostnames should be reported")
}

func TestIsPlausibleHostname(t *testing.T) {
	t.Parallel()

	tests := []struct {
		host     string
		expected bool
	}{
		{"example.com", true},
		{"api.example.com", true},
		{"t.co", true},
		{"intranet", true},
		{"metadata", true},
		{"api", true},
		{"wifi-not-enabled", false},
		{"www.", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, isPlausibleHostname(tt.host))
		})
	}
}

func TestIsKnownLibraryClass(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		class    string
		expected bool
	}{
		{"ACRA collector", "Lorg/acra/collector/MemoryInfoCollector;", true},
		{"Firebase SDK", "Lcom/google/firebase/messaging/FirebaseMessagingService;", true},
		{"Google Play Services", "Lcom/google/android/gms/common/GoogleApiClient;", true},
		{"AndroidX", "Landroidx/work/impl/background/systemjob/SystemJobService;", true},
		{"Sentry", "Lio/sentry/android/core/SentryAndroid;", true},
		// Broad vendor prefixes must NOT match — they include first-party app code.
		{"Google VR (first-party)", "Lcom/google/vr/dynamite/client/DynamiteClient;", false},
		{"Chromium base (first-party)", "Lorg/chromium/base/BundleUtils;", false},
		{"Facebook app code", "Lcom/facebook/appevents/AppEventsLogger;", false},
		// Clearly app-level code.
		{"App code", "Lcom/example/myapp/MainActivity;", false},
		{"OWASP test app", "Lowasp/sat/agoat/RootDetectionActivity;", false},
		{"Obfuscated class", "Lq07;", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, isKnownLibraryClass(tt.class))
		})
	}
}

func TestHardcodedSecrets_Deduplication(t *testing.T) {
	t.Parallel()

	// Same string in two DEX files should produce only one finding.
	df1 := buildTestDEXWithStrings(t, []string{"AKIAIOSFODNN7EXAMPLE"})
	df2 := buildTestDEXWithStrings(t, []string{"AKIAIOSFODNN7EXAMPLE"})

	ctx := &Context{DexFiles: []*dex.File{df1, df2}}
	rule := &hardcodedSecretsRule{}
	findings := rule.Match(ctx)

	assert.Len(t, findings, 1)
}
