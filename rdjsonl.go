package mobilepkg

import (
	"encoding/json"
	"io"
)

// rdjsonlDiagnostic represents a single diagnostic in the reviewdog
// Diagnostic format (rdjsonl). This is a simplified subset of the
// full rdjsonl specification, suitable for check-run annotations.
type rdjsonlDiagnostic struct {
	Message  string           `json:"message"`
	Severity string           `json:"severity,omitempty"`
	Location *rdjsonlLocation `json:"location,omitempty"`
	Code     *rdjsonlCode     `json:"code,omitempty"`
}

type rdjsonlLocation struct {
	Path  string        `json:"path"`
	Range *rdjsonlRange `json:"range,omitempty"`
}

type rdjsonlRange struct {
	Start rdjsonlPosition `json:"start"`
}

type rdjsonlPosition struct {
	Line int `json:"line"`
}

type rdjsonlCode struct {
	Value string `json:"value"`
}

// WriteRDJSONL writes findings in reviewdog's rdjsonl format to w.
// Each finding is written as a single JSON line. This output is
// intended for use with reviewdog's github-check reporter.
//
// The archivePath parameter is used as the file path in the rdjsonl
// output since findings reference archive-internal paths rather than
// repository file paths.
func WriteRDJSONL(w io.Writer, findings []Finding, archivePath string) error {
	enc := json.NewEncoder(w)

	for _, f := range findings {
		sev := mapSeverityToRDJSON(f.Severity)

		diag := rdjsonlDiagnostic{
			Message:  f.Message,
			Severity: sev,
			Code:     &rdjsonlCode{Value: f.ID},
		}

		// Use the first evidence's archive path if available,
		// otherwise fall back to the archive file path.
		path := archivePath
		line := 0
		if len(f.Evidence) > 0 && f.Evidence[0].ArchivePath != "" {
			path = f.Evidence[0].ArchivePath
			line = f.Evidence[0].Line
		}

		diag.Location = &rdjsonlLocation{
			Path: path,
		}
		if line > 0 {
			diag.Location.Range = &rdjsonlRange{
				Start: rdjsonlPosition{Line: line},
			}
		}

		if err := enc.Encode(diag); err != nil {
			return err
		}
	}
	return nil
}

func mapSeverityToRDJSON(s Severity) string {
	switch s {
	case SeverityError:
		return "ERROR"
	case SeverityWarn:
		return "WARNING"
	default:
		return "INFO"
	}
}
