package mobilepkg_test

import (
	"testing"

	"github.com/nao1215/mobilepkg"
)

func TestConfidence_Values(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value mobilepkg.Confidence
		want  string
	}{
		{"high", mobilepkg.ConfidenceHigh, "high"},
		{"medium", mobilepkg.ConfidenceMedium, "medium"},
		{"low", mobilepkg.ConfidenceLow, "low"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if string(tt.value) != tt.want {
				t.Errorf("Confidence = %q, want %q", tt.value, tt.want)
			}
		})
	}
}

func TestFinding_Fields(t *testing.T) {
	t.Parallel()

	f := mobilepkg.Finding{
		ID:         "perm.dangerous.CAMERA",
		Category:   "permission",
		Severity:   mobilepkg.SeverityWarn,
		Confidence: mobilepkg.ConfidenceHigh,
		Message:    "dangerous permission: CAMERA",
		Evidence: []mobilepkg.Evidence{
			{
				ArchivePath:       "AndroidManifest.xml",
				Field:             "uses-permission",
				MatchedTextMasked: "android.permission.CAMERA",
			},
		},
		Fingerprint: "abc123",
	}

	if f.ID != "perm.dangerous.CAMERA" {
		t.Errorf("ID = %q, want %q", f.ID, "perm.dangerous.CAMERA")
	}
	if f.Category != "permission" {
		t.Errorf("Category = %q, want %q", f.Category, "permission")
	}
	if f.Severity != mobilepkg.SeverityWarn {
		t.Errorf("Severity = %q, want %q", f.Severity, mobilepkg.SeverityWarn)
	}
	if f.Confidence != mobilepkg.ConfidenceHigh {
		t.Errorf("Confidence = %q, want %q", f.Confidence, mobilepkg.ConfidenceHigh)
	}
	if len(f.Evidence) != 1 {
		t.Fatalf("Evidence length = %d, want 1", len(f.Evidence))
	}
	if f.Evidence[0].ArchivePath != "AndroidManifest.xml" {
		t.Errorf("Evidence[0].ArchivePath = %q, want %q", f.Evidence[0].ArchivePath, "AndroidManifest.xml")
	}
}
