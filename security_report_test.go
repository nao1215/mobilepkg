package mobilepkg_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/nao1215/mobilepkg"
)

func TestNewReportFile_SchemaVersion(t *testing.T) {
	t.Parallel()

	rf := mobilepkg.NewReportFile(&mobilepkg.InspectResult{}, "0.1.0")
	if rf.SchemaVersion != mobilepkg.SchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", rf.SchemaVersion, mobilepkg.SchemaVersion)
	}
}

func TestNewReportFile_ToolVersion(t *testing.T) {
	t.Parallel()

	rf := mobilepkg.NewReportFile(&mobilepkg.InspectResult{}, "1.2.3")
	if rf.ToolVersion != "1.2.3" {
		t.Errorf("ToolVersion = %q, want %q", rf.ToolVersion, "1.2.3")
	}
}

func TestNewReportFile_NilSlicesNormalized(t *testing.T) {
	t.Parallel()

	ar := mobilepkg.InspectResult{
		Platform: mobilepkg.PlatformAndroid,
		Format:   mobilepkg.FormatAPK,
	}
	rf := mobilepkg.NewReportFile(&ar, "0.1.0")

	var buf bytes.Buffer
	if err := mobilepkg.WriteReportJSON(&buf, rf); err != nil {
		t.Fatalf("WriteReportJSON: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal top-level: %v", err)
	}

	var resultMap map[string]json.RawMessage
	if err := json.Unmarshal(raw["result"], &resultMap); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// Check slices that should be normalized to [].
	for _, field := range []string{"findings", "secret_candidates", "permissions", "exported_components", "network_endpoints", "diagnostics"} {
		v, ok := resultMap[field]
		if !ok {
			t.Errorf("missing field %q in result JSON", field)
			continue
		}
		if string(v) != "[]" {
			t.Errorf("result.%s = %s, want []", field, string(v))
		}
	}
}

func TestWriteReportJSON_ValidJSON(t *testing.T) {
	t.Parallel()

	ar := mobilepkg.InspectResult{
		Platform: mobilepkg.PlatformIOS,
		Format:   mobilepkg.FormatIPA,
		Identity: mobilepkg.Identity{
			Identifier:  "com.example.app",
			DisplayName: "Example App",
		},
		Findings: []mobilepkg.Finding{
			{
				ID:         "perm.camera",
				Category:   "permission",
				Severity:   mobilepkg.SeverityInfo,
				Confidence: mobilepkg.ConfidenceHigh,
				Message:    "app requests camera permission",
				Evidence: []mobilepkg.Evidence{
					{ArchivePath: "Info.plist", Field: "NSCameraUsageDescription"},
				},
				Fingerprint: "fp001",
			},
		},
	}

	rf := mobilepkg.NewReportFile(&ar, "test-0.0.1")

	var buf bytes.Buffer
	if err := mobilepkg.WriteReportJSON(&buf, rf); err != nil {
		t.Fatalf("WriteReportJSON: %v", err)
	}

	var parsed mobilepkg.ReportFile
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if parsed.SchemaVersion != mobilepkg.SchemaVersion {
		t.Errorf("schema_version = %q, want %q", parsed.SchemaVersion, mobilepkg.SchemaVersion)
	}
	if parsed.Result.Identity.Identifier != "com.example.app" {
		t.Errorf("identifier = %q, want %q", parsed.Result.Identity.Identifier, "com.example.app")
	}
	if len(parsed.Result.Findings) != 1 {
		t.Fatalf("findings length = %d, want 1", len(parsed.Result.Findings))
	}
	if parsed.Result.Findings[0].ID != "perm.camera" {
		t.Errorf("finding id = %q, want %q", parsed.Result.Findings[0].ID, "perm.camera")
	}
}

func TestWriteReportJSON_TopLevelKeys(t *testing.T) {
	t.Parallel()

	rf := mobilepkg.NewReportFile(&mobilepkg.InspectResult{
		Platform: mobilepkg.PlatformAndroid,
	}, "0.1.0")

	var buf bytes.Buffer
	if err := mobilepkg.WriteReportJSON(&buf, rf); err != nil {
		t.Fatalf("WriteReportJSON: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, key := range []string{"schema_version", "tool_version", "result"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing top-level key %q", key)
		}
	}
}

// TestWriteReportJSON_IconBytesExcluded is removed because the flat
// AuditResult no longer carries an Icon field. Icon data lives only
// in the inspection-level Report type.
