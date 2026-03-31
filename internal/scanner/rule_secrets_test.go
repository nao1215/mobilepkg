package scanner

import (
	"testing"

	"github.com/nao1215/mobilepkg/internal/dex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHardcodedSecrets_HashBasedID(t *testing.T) {
	t.Parallel()

	df := buildTestDEXWithStrings(t, []string{
		"AKIAIOSFODNN7EXAMPLE",
	})

	ctx := &Context{DexFiles: []*dex.File{df}}
	rule := &hardcodedSecretsRule{}
	findings := rule.Match(ctx)

	require.Len(t, findings, 1)
	// ID should be hash-based, not contain the raw key prefix.
	assert.NotContains(t, findings[0].ID, "AKIA")
	assert.Contains(t, findings[0].ID, "dex.secret.aws_key.")
	// The hash part should be 12 hex chars (6 bytes).
	parts := findIDHashPart(findings[0].ID)
	assert.Len(t, parts, 12, "hash portion should be 12 hex chars")
}

func TestHardcodedSecrets_StableID(t *testing.T) {
	t.Parallel()

	// Same input should produce the same ID across runs.
	df1 := buildTestDEXWithStrings(t, []string{"AKIAIOSFODNN7EXAMPLE"})
	df2 := buildTestDEXWithStrings(t, []string{"AKIAIOSFODNN7EXAMPLE"})

	ctx1 := &Context{DexFiles: []*dex.File{df1}}
	ctx2 := &Context{DexFiles: []*dex.File{df2}}

	rule := &hardcodedSecretsRule{}
	f1 := rule.Match(ctx1)
	f2 := rule.Match(ctx2)

	require.Len(t, f1, 1)
	require.Len(t, f2, 1)
	assert.Equal(t, f1[0].ID, f2[0].ID, "IDs should be stable across runs")
}

func TestHardcodedSecrets_PrivateKey(t *testing.T) {
	t.Parallel()

	df := buildTestDEXWithStrings(t, []string{
		"-----BEGIN RSA PRIVATE KEY-----",
	})

	ctx := &Context{DexFiles: []*dex.File{df}}
	rule := &hardcodedSecretsRule{}
	findings := rule.Match(ctx)

	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Message, "private_key")
}

func TestHardcodedSecrets_FirebaseURL(t *testing.T) {
	t.Parallel()

	df := buildTestDEXWithStrings(t, []string{
		"https://my-app-123.firebaseio.com",
	})

	ctx := &Context{DexFiles: []*dex.File{df}}
	rule := &hardcodedSecretsRule{}
	findings := rule.Match(ctx)

	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Message, "firebase_url")
}

// findIDHashPart extracts the last dot-separated segment from a finding ID.
func findIDHashPart(id string) string {
	parts := splitDots(id)
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func splitDots(s string) []string {
	var parts []string
	start := 0
	for i, c := range s {
		if c == '.' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		parts = append(parts, s[start:])
	}
	return parts
}
