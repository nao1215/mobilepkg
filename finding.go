package mobilepkg

// Confidence represents how certain the analysis is about a [Finding].
type Confidence string

const (
	// ConfidenceHigh indicates strong certainty in the finding.
	ConfidenceHigh Confidence = "high"
	// ConfidenceMedium indicates moderate certainty in the finding.
	ConfidenceMedium Confidence = "medium"
	// ConfidenceLow indicates weak certainty; the finding may be a false positive.
	ConfidenceLow Confidence = "low"
)

// Evidence represents a piece of supporting evidence for a [Finding].
// It locates the relevant data within the analyzed archive.
type Evidence struct {
	// ArchivePath is the path of the file inside the archive where the
	// evidence was found (e.g. "AndroidManifest.xml").
	ArchivePath string `json:"archive_path"`
	// Field identifies a logical field or key within the file
	// (e.g. "android:permission", "NSCameraUsageDescription").
	Field string `json:"field,omitempty"`
	// MatchedTextMasked is the matched value with sensitive parts masked.
	MatchedTextMasked string `json:"matched_text_masked,omitempty"`
	// Line is the line number within the file where the evidence was found.
	// Zero means the line is unknown or not applicable.
	Line int `json:"line,omitempty"`
	// Offset is the byte offset within the file where the evidence was found.
	// Zero means the offset is unknown or not applicable.
	Offset int `json:"offset,omitempty"`
}

// Finding represents a security-relevant observation found during analysis.
// Each finding carries enough context for manual review (message, evidence)
// and for automated baseline comparison (id, fingerprint).
//
// Findings are the primary output of security analysis. They are
// produced by the internal analysis step and included in [InspectResult.Findings].
type Finding struct {
	// ID is a unique, machine-readable identifier for this specific finding
	// instance (e.g. "perm.dangerous.CAMERA", "secret.api_key.1").
	ID string `json:"id"`
	// Category groups related findings (e.g. "permission", "endpoint",
	// "secret", "exported_component", "signing").
	Category string `json:"category"`
	// Severity classifies the importance of the finding.
	Severity Severity `json:"severity"`
	// Confidence indicates how certain the analysis is about this finding.
	Confidence Confidence `json:"confidence"`
	// Message is a human-readable description of the finding.
	Message string `json:"message"`
	// Evidence lists the supporting evidence for this finding.
	Evidence []Evidence `json:"evidence"`
	// Fingerprint is a stable identifier derived from the finding content,
	// used for baseline comparison. Two findings with the same fingerprint
	// across different runs are considered the same finding.
	Fingerprint string `json:"fingerprint"`
}
