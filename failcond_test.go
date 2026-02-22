package mobilepkg_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nao1215/mobilepkg"
)

func TestEvaluateFailConditions_PassesWhenNoFindings(t *testing.T) {
	t.Parallel()

	ar := mobilepkg.InspectResult{}
	policy := mobilepkg.DefaultFailPolicy()
	result := mobilepkg.EvaluateFailConditions(&ar, policy, nil)

	if !result.Passed {
		t.Error("expected pass with no findings")
	}
}

func TestEvaluateFailConditions_FailsOnSeverity(t *testing.T) {
	t.Parallel()

	ar := mobilepkg.InspectResult{
		Findings: []mobilepkg.Finding{
			{ID: "test.1", Severity: mobilepkg.SeverityWarn, Confidence: mobilepkg.ConfidenceHigh},
		},
	}
	policy := mobilepkg.FailPolicy{
		FailOnSeverity:   mobilepkg.SeverityWarn,
		FailOnConfidence: mobilepkg.ConfidenceHigh,
	}
	result := mobilepkg.EvaluateFailConditions(&ar, policy, nil)

	if result.Passed {
		t.Error("expected fail for warn severity + high confidence finding")
	}
	if len(result.TriggeringFindings) != 1 {
		t.Errorf("triggering findings = %d, want 1", len(result.TriggeringFindings))
	}
}

func TestEvaluateFailConditions_NewOnlyFiltersBaseline(t *testing.T) {
	t.Parallel()

	baseline := &mobilepkg.InspectResult{
		Findings: []mobilepkg.Finding{
			{ID: "old.1", Fingerprint: "fp1", Severity: mobilepkg.SeverityWarn, Confidence: mobilepkg.ConfidenceHigh},
		},
	}
	ar := mobilepkg.InspectResult{
		Findings: []mobilepkg.Finding{
			{ID: "old.1", Fingerprint: "fp1", Severity: mobilepkg.SeverityWarn, Confidence: mobilepkg.ConfidenceHigh},
			{ID: "new.1", Fingerprint: "fp2", Severity: mobilepkg.SeverityWarn, Confidence: mobilepkg.ConfidenceHigh},
		},
	}
	policy := mobilepkg.FailPolicy{
		FailOnSeverity:   mobilepkg.SeverityWarn,
		FailOnConfidence: mobilepkg.ConfidenceHigh,
		NewOnly:          true,
	}

	result := mobilepkg.EvaluateFailConditions(&ar, policy, baseline)

	if result.Passed {
		t.Error("expected fail for new finding")
	}
	if len(result.TriggeringFindings) != 1 {
		t.Errorf("triggering findings = %d, want 1", len(result.TriggeringFindings))
	}
	if result.TriggeringFindings[0].ID != "new.1" {
		t.Errorf("triggering finding ID = %q, want %q", result.TriggeringFindings[0].ID, "new.1")
	}
}

func TestEvaluateFailConditions_NewOnlyPassesWhenAllExist(t *testing.T) {
	t.Parallel()

	baseline := &mobilepkg.InspectResult{
		Findings: []mobilepkg.Finding{
			{ID: "existing.1", Fingerprint: "fp1", Severity: mobilepkg.SeverityWarn, Confidence: mobilepkg.ConfidenceHigh},
		},
	}
	ar := mobilepkg.InspectResult{
		Findings: []mobilepkg.Finding{
			{ID: "existing.1", Fingerprint: "fp1", Severity: mobilepkg.SeverityWarn, Confidence: mobilepkg.ConfidenceHigh},
		},
	}
	policy := mobilepkg.FailPolicy{
		FailOnSeverity:   mobilepkg.SeverityWarn,
		FailOnConfidence: mobilepkg.ConfidenceHigh,
		NewOnly:          true,
	}

	result := mobilepkg.EvaluateFailConditions(&ar, policy, baseline)

	if !result.Passed {
		t.Error("expected pass when all findings exist in baseline")
	}
}

func TestDiffFindings(t *testing.T) {
	t.Parallel()

	baseline := []mobilepkg.Finding{
		{ID: "a", Fingerprint: "1"},
		{ID: "b", Fingerprint: "2"},
	}
	current := []mobilepkg.Finding{
		{ID: "b", Fingerprint: "2"},
		{ID: "c", Fingerprint: "3"},
	}

	added, removed := mobilepkg.DiffFindings(baseline, current)

	if len(added) != 1 || added[0].ID != "c" {
		t.Errorf("added = %v, want [{ID:c}]", added)
	}
	if len(removed) != 1 || removed[0].ID != "a" {
		t.Errorf("removed = %v, want [{ID:a}]", removed)
	}
}

func TestLoadReportFile(t *testing.T) {
	t.Parallel()

	ar := mobilepkg.InspectResult{
		Platform: mobilepkg.PlatformAndroid,
		Format:   mobilepkg.FormatAPK,
		Identity: mobilepkg.Identity{Identifier: "com.test"},
	}
	rf := mobilepkg.NewReportFile(&ar, "1.0.0")

	var buf bytes.Buffer
	if err := mobilepkg.WriteReportJSON(&buf, rf); err != nil {
		t.Fatalf("WriteReportJSON: %v", err)
	}

	loaded, err := mobilepkg.LoadReportFile(&buf)
	if err != nil {
		t.Fatalf("LoadReportFile: %v", err)
	}

	if loaded.SchemaVersion != mobilepkg.SchemaVersion {
		t.Errorf("schema_version = %q, want %q", loaded.SchemaVersion, mobilepkg.SchemaVersion)
	}
	if loaded.Result.Identity.Identifier != "com.test" {
		t.Errorf("identifier = %q, want %q", loaded.Result.Identity.Identifier, "com.test")
	}
}

func TestLoadReportFile_SchemaMismatch(t *testing.T) {
	t.Parallel()

	// Manually craft JSON with a different schema version.
	jsonData := `{"schema_version":"99.0.0","tool_version":"1.0.0","result":{"platform":"android"}}`
	_, err := mobilepkg.LoadReportFile(strings.NewReader(jsonData))
	if err == nil {
		t.Fatal("expected error for schema version mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "schema version") {
		t.Errorf("error should mention schema version, got: %v", err)
	}
}

func TestDefaultFailPolicy(t *testing.T) {
	t.Parallel()

	policy := mobilepkg.DefaultFailPolicy()
	if policy.FailOnSeverity != mobilepkg.SeverityWarn {
		t.Errorf("FailOnSeverity = %q, want %q", policy.FailOnSeverity, mobilepkg.SeverityWarn)
	}
	if policy.FailOnConfidence != "" {
		t.Errorf("FailOnConfidence = %q, want empty", policy.FailOnConfidence)
	}
	if policy.NewOnly {
		t.Error("NewOnly should be false by default")
	}
}
