package mobilepkg_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nao1215/mobilepkg"
)

func TestWriteSummaryMarkdown_BasicOutput(t *testing.T) {
	t.Parallel()

	ar := mobilepkg.InspectResult{
		Platform: mobilepkg.PlatformAndroid,
		Format:   mobilepkg.FormatAPK,
		Identity: mobilepkg.Identity{
			Identifier:  "com.example.app",
			DisplayName: "Example App",
		},
		Version: mobilepkg.Version{Marketing: "1.0.0", Build: "42"},
		ExportedComponents: []mobilepkg.ExportedComponent{
			{Kind: "activity", Name: "com.example.MainActivity", Exported: true},
		},
		Findings: []mobilepkg.Finding{
			{
				ID:         "exported.activity.MainActivity",
				Category:   "exported_component",
				Severity:   mobilepkg.SeverityInfo,
				Confidence: mobilepkg.ConfidenceHigh,
				Message:    "exported activity: com.example.MainActivity",
			},
		},
	}

	rf := mobilepkg.NewReportFile(&ar, "0.1.0")
	var buf bytes.Buffer
	err := mobilepkg.WriteSummaryMarkdown(&buf, rf)
	if err != nil {
		t.Fatalf("WriteSummaryMarkdown: %v", err)
	}

	output := buf.String()
	checks := []string{
		"# mobilepkg Inspection Report",
		"com.example.app",
		"Example App",
		"1.0.0",
		"Summary Metrics",
		"Exported Components",
		"mobilepkg 0.1.0",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("output missing %q", check)
		}
	}
}

func TestWriteSummaryMarkdown_TopFindingsFirst(t *testing.T) {
	t.Parallel()

	ar := mobilepkg.InspectResult{
		Platform: mobilepkg.PlatformAndroid,
		Format:   mobilepkg.FormatAPK,
		Identity: mobilepkg.Identity{Identifier: "com.example.app"},
		Findings: []mobilepkg.Finding{
			{ID: "warn.1", Severity: mobilepkg.SeverityWarn, Confidence: mobilepkg.ConfidenceHigh, Message: "warning finding"},
			{ID: "info.1", Severity: mobilepkg.SeverityInfo, Confidence: mobilepkg.ConfidenceHigh, Message: "info finding"},
		},
	}

	rf := mobilepkg.NewReportFile(&ar, "0.1.0")
	var buf bytes.Buffer
	if err := mobilepkg.WriteSummaryMarkdown(&buf, rf); err != nil {
		t.Fatalf("WriteSummaryMarkdown: %v", err)
	}

	output := buf.String()

	// Top Findings should appear before Summary Metrics.
	topIdx := strings.Index(output, "Top Findings")
	metricsIdx := strings.Index(output, "Summary Metrics")

	if topIdx < 0 {
		t.Fatal("output missing 'Top Findings' section")
	}
	if metricsIdx < 0 {
		t.Fatal("output missing 'Summary Metrics' section")
	}
	if topIdx > metricsIdx {
		t.Error("'Top Findings' should appear before 'Summary Metrics'")
	}
}

func TestWriteSummaryMarkdown_WithDiff(t *testing.T) {
	t.Parallel()

	ar := mobilepkg.InspectResult{
		Platform: mobilepkg.PlatformAndroid,
		Identity: mobilepkg.Identity{Identifier: "com.example.app"},
		Diff: &mobilepkg.Diff{
			VersionChanged: true,
			AddedPermissions: []mobilepkg.Permission{
				{RawName: "android.permission.INTERNET", Source: "manifest"},
			},
		},
	}

	rf := mobilepkg.NewReportFile(&ar, "0.1.0")
	var buf bytes.Buffer
	if err := mobilepkg.WriteSummaryMarkdown(&buf, rf); err != nil {
		t.Fatalf("WriteSummaryMarkdown: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Changes from Baseline") {
		t.Error("output missing 'Changes from Baseline' section")
	}
	if !strings.Contains(output, "android.permission.INTERNET") {
		t.Error("output missing added permission")
	}
}

func TestWriteSummaryMarkdown_Verdict(t *testing.T) {
	t.Parallel()

	ar := mobilepkg.InspectResult{
		Platform: mobilepkg.PlatformAndroid,
		Identity: mobilepkg.Identity{Identifier: "com.example.app"},
		Findings: []mobilepkg.Finding{
			{ID: "manifest.debuggable", Severity: mobilepkg.SeverityError, Confidence: mobilepkg.ConfidenceHigh, Message: "debuggable"},
		},
	}

	verdict := mobilepkg.Check(&ar, mobilepkg.FailPolicy{
		FailOnSeverity: mobilepkg.SeverityWarn,
	})

	rf := mobilepkg.NewReportFile(&ar, "0.1.0")
	rf.Verdict = &verdict

	var buf bytes.Buffer
	if err := mobilepkg.WriteSummaryMarkdown(&buf, rf); err != nil {
		t.Fatalf("WriteSummaryMarkdown: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Verdict") {
		t.Error("output missing Verdict section")
	}
	if !strings.Contains(output, "FAILED") {
		t.Error("output missing FAILED indicator")
	}
}

func TestWriteSummaryMarkdown_DeepLinks(t *testing.T) {
	t.Parallel()

	ar := mobilepkg.InspectResult{
		Platform: mobilepkg.PlatformAndroid,
		Identity: mobilepkg.Identity{Identifier: "com.example.app"},
		ExportedComponents: []mobilepkg.ExportedComponent{
			{
				Kind: "activity", Name: "com.example.DeepLinkActivity", Exported: true,
				IntentFilters: []mobilepkg.IntentFilter{
					{
						Actions:    []string{"android.intent.action.VIEW"},
						Categories: []string{"android.intent.category.DEFAULT", "android.intent.category.BROWSABLE"},
						Data:       []mobilepkg.DataSpec{{Scheme: "https", Host: "example.com", Path: "/app"}},
					},
				},
			},
		},
	}

	rf := mobilepkg.NewReportFile(&ar, "0.1.0")
	var buf bytes.Buffer
	if err := mobilepkg.WriteSummaryMarkdown(&buf, rf); err != nil {
		t.Fatalf("WriteSummaryMarkdown: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Deep Links") {
		t.Error("output missing Deep Links section")
	}
	if !strings.Contains(output, "https://example.com/app") {
		t.Error("output missing deep link URL")
	}
}

func TestWriteSummaryMarkdown_ProviderAuthorities(t *testing.T) {
	t.Parallel()

	ar := mobilepkg.InspectResult{
		Platform: mobilepkg.PlatformAndroid,
		Identity: mobilepkg.Identity{Identifier: "com.example.app"},
		ExportedComponents: []mobilepkg.ExportedComponent{
			{Kind: "provider", Name: "com.example.MyProvider", Exported: true, Authorities: "com.example.provider"},
		},
	}

	rf := mobilepkg.NewReportFile(&ar, "0.1.0")
	var buf bytes.Buffer
	if err := mobilepkg.WriteSummaryMarkdown(&buf, rf); err != nil {
		t.Fatalf("WriteSummaryMarkdown: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "com.example.provider") {
		t.Error("output missing provider authorities")
	}
}
