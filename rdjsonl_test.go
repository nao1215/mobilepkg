package mobilepkg_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nao1215/mobilepkg"
)

func TestWriteRDJSONL_OutputFormat(t *testing.T) {
	t.Parallel()

	findings := []mobilepkg.Finding{
		{
			ID:       "test.1",
			Severity: mobilepkg.SeverityWarn,
			Message:  "test warning",
			Evidence: []mobilepkg.Evidence{
				{ArchivePath: "AndroidManifest.xml", Line: 10},
			},
		},
		{
			ID:       "test.2",
			Severity: mobilepkg.SeverityError,
			Message:  "test error",
		},
	}

	var buf bytes.Buffer
	err := mobilepkg.WriteRDJSONL(&buf, findings, "app.apk")
	if err != nil {
		t.Fatalf("WriteRDJSONL: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	// Parse first line.
	var diag1 map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &diag1); err != nil {
		t.Fatalf("parse line 1: %v", err)
	}
	if diag1["message"] != "test warning" {
		t.Errorf("line 1 message = %v, want %q", diag1["message"], "test warning")
	}
	if diag1["severity"] != "WARNING" {
		t.Errorf("line 1 severity = %v, want %q", diag1["severity"], "WARNING")
	}

	// Verify location uses evidence archive path.
	loc, ok := diag1["location"].(map[string]any)
	if !ok {
		t.Fatal("line 1 missing location")
	}
	if loc["path"] != "AndroidManifest.xml" {
		t.Errorf("line 1 path = %v, want %q", loc["path"], "AndroidManifest.xml")
	}

	// Parse second line - should use archive path fallback.
	var diag2 map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &diag2); err != nil {
		t.Fatalf("parse line 2: %v", err)
	}
	loc2, ok := diag2["location"].(map[string]any)
	if !ok {
		t.Fatal("line 2 missing location")
	}
	if loc2["path"] != "app.apk" {
		t.Errorf("line 2 path = %v, want %q", loc2["path"], "app.apk")
	}
}

func TestWriteRDJSONL_EmptyFindings(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := mobilepkg.WriteRDJSONL(&buf, nil, "app.apk")
	if err != nil {
		t.Fatalf("WriteRDJSONL: %v", err)
	}

	if buf.Len() != 0 {
		t.Errorf("expected empty output for nil findings, got %d bytes", buf.Len())
	}
}

func TestWriteRDJSONL_SeverityMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		severity mobilepkg.Severity
		want     string
	}{
		{mobilepkg.SeverityError, "ERROR"},
		{mobilepkg.SeverityWarn, "WARNING"},
		{mobilepkg.SeverityInfo, "INFO"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			t.Parallel()

			findings := []mobilepkg.Finding{
				{ID: "test", Severity: tt.severity, Message: "msg"},
			}

			var buf bytes.Buffer
			if err := mobilepkg.WriteRDJSONL(&buf, findings, "app.apk"); err != nil {
				t.Fatalf("WriteRDJSONL: %v", err)
			}

			var diag map[string]any
			if err := json.Unmarshal(buf.Bytes(), &diag); err != nil {
				t.Fatalf("parse: %v", err)
			}
			if diag["severity"] != tt.want {
				t.Errorf("severity = %v, want %q", diag["severity"], tt.want)
			}
		})
	}
}
