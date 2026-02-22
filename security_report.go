package mobilepkg

import (
	"encoding/json"
	"io"
)

// SchemaVersion is the current schema version of the report.json output.
const SchemaVersion = "1.0.0"

// ReportFile is the top-level structure for the report.json output file.
// It wraps an [InspectResult] with metadata required for tooling.
// Use [WriteReportJSON] to serialize it.
type ReportFile struct {
	// SchemaVersion identifies the format version of this report file.
	SchemaVersion string `json:"schema_version"`
	// ToolVersion identifies the version of the tool that produced this report.
	ToolVersion string `json:"tool_version"`
	// Result contains the inspection output (metadata + findings + secrets + diff).
	Result InspectResult `json:"result"`
	// Verdict holds the fail-condition evaluation result, if a policy was
	// applied. Nil when no policy was evaluated.
	Verdict *FailResult `json:"verdict,omitempty"`
}

// NewReportFile creates a [ReportFile] from an [InspectResult].
// Nil slices are normalized to empty slices so that JSON output
// contains [] instead of null.
func NewReportFile(ir *InspectResult, toolVersion string) ReportFile {
	normalizeSlices(ir)
	return ReportFile{
		SchemaVersion: SchemaVersion,
		ToolVersion:   toolVersion,
		Result:        *ir,
	}
}

// WriteReportJSON writes the report as pretty-printed JSON to w.
func WriteReportJSON(w io.Writer, rf ReportFile) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rf)
}

// normalizeSlices ensures no nil slices in the inspection result, so JSON
// serialization produces [] instead of null.
func normalizeSlices(ir *InspectResult) {
	if ir.Permissions == nil {
		ir.Permissions = []Permission{}
	}
	if ir.ExportedComponents == nil {
		ir.ExportedComponents = []ExportedComponent{}
	}
	if ir.NetworkEndpoints == nil {
		ir.NetworkEndpoints = []NetworkEndpoint{}
	}
	if ir.Diagnostics == nil {
		ir.Diagnostics = []Diagnostic{}
	}
	if ir.Findings == nil {
		ir.Findings = []Finding{}
	}
	for i := range ir.Findings {
		if ir.Findings[i].Evidence == nil {
			ir.Findings[i].Evidence = []Evidence{}
		}
	}
	if ir.SecretCandidates == nil {
		ir.SecretCandidates = []SecretCandidate{}
	}
}
