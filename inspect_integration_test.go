package mobilepkg_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/nao1215/mobilepkg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Integration tests covering the primary InspectFile → InspectResult flow
// with synthetic test fixtures.

func TestInspectFile_IPA_FullResult(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ipaPath := createTestIPA(t, dir)

	result, err := mobilepkg.InspectFile(context.Background(), ipaPath)
	require.NoError(t, err)

	// Metadata.
	assert.Equal(t, mobilepkg.PlatformIOS, result.Platform)
	assert.Equal(t, mobilepkg.FormatIPA, result.Format)
	assert.Equal(t, "com.example.testapp", result.Identity.Identifier)
	assert.Equal(t, "Test App", result.Identity.DisplayName)
	assert.Equal(t, "2.0.1", result.Version.Marketing)
	assert.Equal(t, "executable", result.Entry.Kind)

	// Permissions.
	require.GreaterOrEqual(t, len(result.Permissions), 2)

	// Findings should be generated (at least info-level for permissions).
	// The exact count depends on analysis rules.
	assert.NotNil(t, result.Diagnostics)

	// Should be serializable to JSON.
	var buf bytes.Buffer
	rf := mobilepkg.NewReportFile(result, "test")
	err = mobilepkg.WriteReportJSON(&buf, rf)
	require.NoError(t, err)

	var parsed mobilepkg.ReportFile
	err = json.Unmarshal(buf.Bytes(), &parsed)
	require.NoError(t, err)
	assert.Equal(t, "com.example.testapp", parsed.Result.Identity.Identifier)
}

func TestInspectFile_AAB_FullResult(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	aabPath := createTestAAB(t, dir)

	result, err := mobilepkg.InspectFile(context.Background(), aabPath)
	require.NoError(t, err)

	assert.Equal(t, mobilepkg.PlatformAndroid, result.Platform)
	assert.Equal(t, mobilepkg.FormatAAB, result.Format)
	assert.Equal(t, "com.example.aabtest", result.Identity.Identifier)
	assert.Equal(t, "3.0.0", result.Version.Marketing)
	assert.GreaterOrEqual(t, len(result.Permissions), 2)
}

func TestInspect_Reader(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ipaPath := createTestIPA(t, dir)
	data, err := os.ReadFile(ipaPath)
	require.NoError(t, err)

	result, err := mobilepkg.Inspect(context.Background(), bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)

	assert.Equal(t, mobilepkg.PlatformIOS, result.Platform)
	assert.Equal(t, mobilepkg.FormatIPA, result.Format)
	assert.Equal(t, "com.example.testapp", result.Identity.Identifier)
}

func TestInspectFile_Baseline(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ipaPath := createTestIPA(t, dir)

	result1, err := mobilepkg.InspectFile(context.Background(), ipaPath)
	require.NoError(t, err)

	// Use the same file as baseline — should show no changes.
	result2, err := mobilepkg.InspectWithBaseline(context.Background(), ipaPath, result1)
	require.NoError(t, err)
	require.NotNil(t, result2.Diff)
	assert.False(t, result2.Diff.VersionChanged)
	assert.False(t, result2.Diff.IdentityChanged)
}

func TestInspectFile_JSON_RoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ipaPath := createTestIPA(t, dir)

	result, err := mobilepkg.InspectFile(context.Background(), ipaPath)
	require.NoError(t, err)

	// Write to JSON.
	var buf bytes.Buffer
	rf := mobilepkg.NewReportFile(result, "1.0.0")
	err = mobilepkg.WriteReportJSON(&buf, rf)
	require.NoError(t, err)

	// Load back.
	loaded, err := mobilepkg.LoadReportFile(&buf)
	require.NoError(t, err)

	assert.Equal(t, result.Identity.Identifier, loaded.Result.Identity.Identifier)
	assert.Equal(t, result.Version.Marketing, loaded.Result.Version.Marketing)
}

func TestInspectFile_Markdown_Output(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ipaPath := createTestIPA(t, dir)

	result, err := mobilepkg.InspectFile(context.Background(), ipaPath)
	require.NoError(t, err)

	rf := mobilepkg.NewReportFile(result, "test")

	var buf bytes.Buffer
	err = mobilepkg.WriteSummaryMarkdown(&buf, rf)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "mobilepkg Inspection Report")
	assert.Contains(t, output, "com.example.testapp")
}

func TestInspectFile_Markdown_WithVerdict(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ipaPath := createTestIPA(t, dir)

	result, err := mobilepkg.InspectFile(context.Background(), ipaPath)
	require.NoError(t, err)

	verdict := mobilepkg.Check(result, mobilepkg.FailPolicy{
		FailOnSeverity:   mobilepkg.SeverityInfo,
		FailOnConfidence: mobilepkg.ConfidenceLow,
	})

	rf := mobilepkg.NewReportFile(result, "test")
	rf.Verdict = &verdict

	var buf bytes.Buffer
	err = mobilepkg.WriteSummaryMarkdown(&buf, rf)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Verdict")
}

func TestLoadReportFile_SchemaMismatch_Integration(t *testing.T) {
	t.Parallel()

	jsonData := `{"schema_version":"99.0.0","tool_version":"1.0.0","result":{"platform":"android"}}`
	_, err := mobilepkg.LoadReportFile(strings.NewReader(jsonData))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "schema")
}

func TestCheck_Pass(t *testing.T) {
	t.Parallel()

	ir := &mobilepkg.InspectResult{
		Platform: mobilepkg.PlatformAndroid,
		Findings: []mobilepkg.Finding{
			{ID: "info.1", Severity: mobilepkg.SeverityInfo, Confidence: mobilepkg.ConfidenceHigh},
		},
	}

	// Only severity is checked. Info-level finding should pass with warn threshold.
	verdict := mobilepkg.Check(ir, mobilepkg.FailPolicy{
		FailOnSeverity: mobilepkg.SeverityWarn,
	})
	assert.True(t, verdict.Passed)
}

func TestCheck_Fail(t *testing.T) {
	t.Parallel()

	ir := &mobilepkg.InspectResult{
		Platform: mobilepkg.PlatformAndroid,
		Findings: []mobilepkg.Finding{
			{ID: "error.1", Severity: mobilepkg.SeverityError, Confidence: mobilepkg.ConfidenceHigh},
		},
	}

	verdict := mobilepkg.Check(ir, mobilepkg.FailPolicy{
		FailOnSeverity: mobilepkg.SeverityWarn,
	})
	assert.False(t, verdict.Passed)
	assert.Len(t, verdict.TriggeringFindings, 1)
}

func TestCompare_Integration(t *testing.T) {
	t.Parallel()

	old := &mobilepkg.InspectResult{
		Platform: mobilepkg.PlatformAndroid,
		Version:  mobilepkg.Version{Marketing: "1.0", Build: "1"},
		Permissions: []mobilepkg.Permission{
			{RawName: "android.permission.INTERNET"},
		},
	}
	current := &mobilepkg.InspectResult{
		Platform: mobilepkg.PlatformAndroid,
		Version:  mobilepkg.Version{Marketing: "2.0", Build: "2"},
		Permissions: []mobilepkg.Permission{
			{RawName: "android.permission.INTERNET"},
			{RawName: "android.permission.CAMERA"},
		},
	}

	diff := mobilepkg.Compare(old, current)
	assert.True(t, diff.VersionChanged)
	assert.Len(t, diff.AddedPermissions, 1)
	assert.Equal(t, "android.permission.CAMERA", diff.AddedPermissions[0].RawName)
}
