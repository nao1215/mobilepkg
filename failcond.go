package mobilepkg

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// FailPolicy configures the conditions under which an inspection
// is considered failed. A finding triggers failure if it meets ANY
// of the specified thresholds (OR logic). Use [Check] or
// [EvaluateFailConditions] to produce a pass/fail verdict.
type FailPolicy struct {
	// FailOnSeverity fails if any finding has severity >= this value.
	// Empty string means severity is not checked.
	FailOnSeverity Severity `json:"fail_on_severity,omitempty"`
	// FailOnConfidence fails if any finding has confidence >= this value.
	// Empty string means confidence is not checked.
	FailOnConfidence Confidence `json:"fail_on_confidence,omitempty"`
	// NewOnly restricts fail checks to new findings only. When true and
	// a baseline is provided to [EvaluateFailConditions], only findings
	// not present in the baseline trigger failure. Has no effect when
	// used with [Check] (which has no baseline).
	NewOnly bool `json:"new_only,omitempty"`
}

// DefaultFailPolicy returns a [FailPolicy] suitable for CI use:
//   - fail_on_severity: warn (fails on warn or error)
//   - fail_on_confidence: (empty — not checked)
//   - new_only: false
func DefaultFailPolicy() FailPolicy {
	return FailPolicy{
		FailOnSeverity: SeverityWarn,
	}
}

// FailResult holds the outcome of fail condition evaluation.
type FailResult struct {
	// Passed is true if no fail conditions were triggered.
	Passed bool `json:"passed"`
	// Reasons lists the reasons for failure, if any.
	Reasons []string `json:"reasons,omitempty"`
	// TriggeringFindings lists the findings that triggered failure.
	TriggeringFindings []Finding `json:"triggering_findings,omitempty"`
}

// Check evaluates the inspection result against the given fail policy
// and returns whether the check passes or fails.
//
// This is the simplified API for CI quality gates. For baseline
// comparison, use [EvaluateFailConditions] instead.
func Check(result *InspectResult, policy FailPolicy) FailResult {
	return EvaluateFailConditions(result, policy, nil)
}

// EvaluateFailConditions evaluates the inspection result against the given
// fail policy and returns whether the check passes or fails.
//
// A finding triggers failure if it matches ANY specified threshold:
//   - If FailOnSeverity is set and the finding's severity >= threshold, it fails.
//   - If FailOnConfidence is set and the finding's confidence >= threshold, it fails.
//
// When policy.NewOnly is true and baseline is non-nil, only findings
// not present in the baseline are considered.
func EvaluateFailConditions(ir *InspectResult, policy FailPolicy, baseline *InspectResult) FailResult {
	result := FailResult{Passed: true}

	findings := ir.Findings
	if policy.NewOnly && baseline != nil {
		findings = newFindings(baseline.Findings, ir.Findings)
	}

	severityRank := map[Severity]int{
		SeverityInfo:  0,
		SeverityWarn:  1,
		SeverityError: 2,
	}
	confidenceRank := map[Confidence]int{
		ConfidenceLow:    0,
		ConfidenceMedium: 1,
		ConfidenceHigh:   2,
	}

	minSev := severityRank[policy.FailOnSeverity]
	minConf := confidenceRank[policy.FailOnConfidence]

	for _, f := range findings {
		sev := severityRank[f.Severity]
		conf := confidenceRank[f.Confidence]

		sevMatch := policy.FailOnSeverity != "" && sev >= minSev
		confMatch := policy.FailOnConfidence != "" && conf >= minConf

		// OR logic: either condition triggers failure.
		if sevMatch || confMatch {
			result.Passed = false
			result.TriggeringFindings = append(result.TriggeringFindings, f)
			result.Reasons = append(result.Reasons,
				fmt.Sprintf("finding %q: severity=%s confidence=%s", f.ID, f.Severity, f.Confidence))
		}
	}

	return result
}

// newFindings returns findings in current that are not present in baseline.
// The comparison key is ID + Fingerprint.
func newFindings(baseline, current []Finding) []Finding {
	baseSet := make(map[string]struct{}, len(baseline))
	for _, f := range baseline {
		baseSet[f.ID+"\x00"+f.Fingerprint] = struct{}{}
	}
	var added []Finding
	for _, f := range current {
		if _, exists := baseSet[f.ID+"\x00"+f.Fingerprint]; !exists {
			added = append(added, f)
		}
	}
	return added
}

// DiffFindings compares two slices of [Finding] and returns which were
// added and which were removed. The comparison key is ID + Fingerprint.
func DiffFindings(baseline, current []Finding) (added, removed []Finding) {
	baseSet := make(map[string]struct{}, len(baseline))
	for _, f := range baseline {
		baseSet[f.ID+"\x00"+f.Fingerprint] = struct{}{}
	}
	currSet := make(map[string]struct{}, len(current))
	for _, f := range current {
		currSet[f.ID+"\x00"+f.Fingerprint] = struct{}{}
	}
	for _, f := range current {
		if _, exists := baseSet[f.ID+"\x00"+f.Fingerprint]; !exists {
			added = append(added, f)
		}
	}
	for _, f := range baseline {
		if _, exists := currSet[f.ID+"\x00"+f.Fingerprint]; !exists {
			removed = append(removed, f)
		}
	}
	sort.Slice(added, func(i, j int) bool { return added[i].ID < added[j].ID })
	sort.Slice(removed, func(i, j int) bool { return removed[i].ID < removed[j].ID })
	return added, removed
}

// LoadReportFile reads and parses a report.json file from the given reader.
// It validates that the schema_version matches [SchemaVersion]; mismatched
// versions produce a descriptive error so that stale baselines are caught
// early rather than causing subtle diff inaccuracies.
func LoadReportFile(r io.Reader) (ReportFile, error) {
	var rf ReportFile
	if err := json.NewDecoder(r).Decode(&rf); err != nil {
		return ReportFile{}, fmt.Errorf("failed to parse report file: %w", err)
	}
	if rf.SchemaVersion != SchemaVersion {
		return ReportFile{}, fmt.Errorf(
			"schema version mismatch: file has %q, expected %q — regenerate the report with the current tool version",
			rf.SchemaVersion, SchemaVersion,
		)
	}
	return rf, nil
}
