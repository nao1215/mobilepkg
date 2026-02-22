package mobilepkg

import (
	"fmt"
	"io"
	"strings"

	md "github.com/nao1215/markdown"
)

// WriteSummaryMarkdown writes a human-readable Markdown summary of
// the inspection result to w. The layout leads with the most actionable
// information — top findings and new risks — before metrics tables.
//
// If the result includes a baseline diff (ar.Diff != nil), the
// summary highlights changes compared to the previous report.
func WriteSummaryMarkdown(w io.Writer, rf ReportFile) error {
	ar := rf.Result

	m := md.NewMarkdown(w)

	m.H1("mobilepkg Inspection Report")

	// Package overview.
	m.H2("Package")
	m.Table(md.TableSet{
		Header: []string{"Field", "Value"},
		Rows: [][]string{
			{"Platform", string(ar.Platform)},
			{"Format", string(ar.Format)},
			{"Identifier", ar.Identity.Identifier},
			{"Display Name", ar.Identity.DisplayName},
			{"Version", fmt.Sprintf("%s (build %s)", ar.Version.Marketing, ar.Version.Build)},
			{"Min SDK", ar.SDK.MinSDK},
		},
	})

	// Top Findings — the most actionable section, placed first.
	warnOrAbove := filterFindings(ar.Findings, SeverityWarn)
	if len(warnOrAbove) > 0 {
		m.H2("Top Findings")
		m.Warning(fmt.Sprintf("%d finding(s) at warning severity or above.", len(warnOrAbove)))
		rows := make([][]string, 0, len(warnOrAbove))
		for _, f := range warnOrAbove {
			rows = append(rows, []string{f.ID, string(f.Severity), string(f.Confidence), f.Message})
		}
		m.Table(md.TableSet{
			Header: []string{"ID", "Severity", "Confidence", "Message"},
			Rows:   rows,
		})
	}

	// New Risk Summary (when baseline diff is available).
	if ar.Diff != nil {
		m.H2("Changes from Baseline")
		items := []string{
			fmt.Sprintf("Identity changed: %s", boolToYesNo(ar.Diff.IdentityChanged)),
			fmt.Sprintf("Version changed: %s", boolToYesNo(ar.Diff.VersionChanged)),
			fmt.Sprintf("Entry point changed: %s", boolToYesNo(ar.Diff.EntryChanged)),
		}
		if len(ar.Diff.AddedPermissions) > 0 {
			items = append(items, fmt.Sprintf("Added permissions: %d", len(ar.Diff.AddedPermissions)))
			for _, p := range ar.Diff.AddedPermissions {
				items = append(items, fmt.Sprintf("  + %s (%s)", p.RawName, p.Source))
			}
		}
		if len(ar.Diff.RemovedPermissions) > 0 {
			items = append(items, fmt.Sprintf("Removed permissions: %d", len(ar.Diff.RemovedPermissions)))
		}
		m.BulletList(items...)
	}

	// Secret candidates.
	if len(ar.SecretCandidates) > 0 {
		highCount := 0
		for _, sc := range ar.SecretCandidates {
			if sc.Confidence == ConfidenceHigh {
				highCount++
			}
		}
		m.H2("Secret Candidates")
		if highCount > 0 {
			m.Warning(fmt.Sprintf("%d high-confidence secret candidate(s) detected.", highCount))
		}
		m.PlainTextf("%d candidate(s) total. See report.json for details.", len(ar.SecretCandidates))
	}

	// Exported components.
	if len(ar.ExportedComponents) > 0 {
		m.H2("Exported Components")
		rows := make([][]string, 0, len(ar.ExportedComponents))
		for _, ec := range ar.ExportedComponents {
			rows = append(rows, []string{ec.Kind, ec.Name, ec.Permission, ec.Authorities})
		}
		m.Table(md.TableSet{
			Header: []string{"Kind", "Name", "Required Permission", "Authorities"},
			Rows:   rows,
		})

		// Deep links extracted from intent-filter data specs.
		deepLinks := collectDeepLinks(ar.ExportedComponents)
		if len(deepLinks) > 0 {
			m.H3("Deep Links")
			rows := make([][]string, 0, len(deepLinks))
			for _, dl := range deepLinks {
				rows = append(rows, []string{dl.component, dl.uri, dl.actions})
			}
			m.Table(md.TableSet{
				Header: []string{"Component", "URI Pattern", "Actions"},
				Rows:   rows,
			})
		}

		// Intent-filter details (collapsed).
		var filterDetails []string
		for _, ec := range ar.ExportedComponents {
			for _, f := range ec.IntentFilters {
				line := fmt.Sprintf("**%s** — actions: %s, categories: %s",
					ec.Name,
					strings.Join(f.Actions, ", "),
					strings.Join(f.Categories, ", "))
				filterDetails = append(filterDetails, line)
			}
		}
		if len(filterDetails) > 0 {
			m.Details(fmt.Sprintf("Intent-filter details (%d)", len(filterDetails)),
				buildBulletListString(filterDetails))
		}
	}

	// Network endpoints.
	if len(ar.NetworkEndpoints) > 0 {
		m.H2("Network Endpoints")
		rows := make([][]string, 0, len(ar.NetworkEndpoints))
		for _, ep := range ar.NetworkEndpoints {
			host := ep.Host
			if ep.Scheme != "" && host != "" {
				host = ep.Scheme + "://" + host
			}
			if ep.Path != "" {
				host += ep.Path
			}
			rows = append(rows, []string{host, ep.Source, string(ep.Confidence)})
		}
		m.Table(md.TableSet{
			Header: []string{"Endpoint", "Source", "Confidence"},
			Rows:   rows,
		})
	}

	// Metrics (lower priority — further down).
	m.H2("Summary Metrics")
	sevCounts := countBySeverity(ar.Findings)
	m.Table(md.TableSet{
		Header: []string{"Metric", "Count"},
		Rows: [][]string{
			{"Total findings", fmt.Sprintf("%d", len(ar.Findings))},
			{"Error", fmt.Sprintf("%d", sevCounts[SeverityError])},
			{"Warning", fmt.Sprintf("%d", sevCounts[SeverityWarn])},
			{"Info", fmt.Sprintf("%d", sevCounts[SeverityInfo])},
			{"Exported components", fmt.Sprintf("%d", len(ar.ExportedComponents))},
			{"Network endpoints", fmt.Sprintf("%d", len(ar.NetworkEndpoints))},
			{"Secret candidates", fmt.Sprintf("%d", len(ar.SecretCandidates))},
			{"Permissions", fmt.Sprintf("%d", len(ar.Permissions))},
		},
	})

	// Permissions (collapsed).
	if len(ar.Permissions) > 0 {
		rows := make([][]string, 0, len(ar.Permissions))
		for _, p := range ar.Permissions {
			rows = append(rows, []string{p.RawName, p.Canonical, p.Source})
		}
		m.Details(fmt.Sprintf("Permissions (%d)", len(ar.Permissions)),
			buildTableString([]string{"Permission", "Canonical", "Source"}, rows))
	}

	// All findings (collapsed if many).
	if len(ar.Findings) > len(warnOrAbove) {
		infoFindings := filterFindingsBelow(ar.Findings, SeverityWarn)
		if len(infoFindings) > 0 {
			rows := make([][]string, 0, len(infoFindings))
			for _, f := range infoFindings {
				rows = append(rows, []string{f.ID, string(f.Severity), f.Message})
			}
			m.Details(fmt.Sprintf("Info-level findings (%d)", len(infoFindings)),
				buildTableString([]string{"ID", "Severity", "Message"}, rows))
		}
	}

	// Signing info.
	if ar.Signing != nil && len(ar.Signing.Certificates) > 0 {
		m.Details("Signing certificates", buildSigningTable(ar.Signing))
	}

	// Diagnostics.
	if len(ar.Diagnostics) > 0 {
		items := make([]string, 0, len(ar.Diagnostics))
		for _, d := range ar.Diagnostics {
			items = append(items, fmt.Sprintf("[%s] %s: %s", d.Severity, d.Code, d.Message))
		}
		m.Details(fmt.Sprintf("Diagnostics (%d)", len(ar.Diagnostics)),
			buildBulletListString(items))
	}

	// Verdict (if a fail policy was evaluated).
	if rf.Verdict != nil {
		m.H2("Verdict")
		if rf.Verdict.Passed {
			m.PlainTextf("PASSED")
		} else {
			m.Warning("FAILED")
			items := make([]string, 0, len(rf.Verdict.Reasons))
			items = append(items, rf.Verdict.Reasons...)
			if len(items) > 0 {
				m.BulletList(items...)
			}
		}
	}

	m.HorizontalRule()
	m.PlainTextf("Generated by mobilepkg %s (schema %s)", rf.ToolVersion, rf.SchemaVersion)

	return m.Build()
}

func filterFindings(findings []Finding, minSeverity Severity) []Finding {
	rank := map[Severity]int{SeverityInfo: 0, SeverityWarn: 1, SeverityError: 2}
	threshold := rank[minSeverity]
	var result []Finding
	for _, f := range findings {
		if rank[f.Severity] >= threshold {
			result = append(result, f)
		}
	}
	return result
}

func filterFindingsBelow(findings []Finding, minSeverity Severity) []Finding {
	rank := map[Severity]int{SeverityInfo: 0, SeverityWarn: 1, SeverityError: 2}
	threshold := rank[minSeverity]
	var result []Finding
	for _, f := range findings {
		if rank[f.Severity] < threshold {
			result = append(result, f)
		}
	}
	return result
}

func countBySeverity(findings []Finding) map[Severity]int {
	counts := make(map[Severity]int)
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

func boolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

func buildTableString(header []string, rows [][]string) string {
	var buf strings.Builder
	m := md.NewMarkdown(&buf)
	m.Table(md.TableSet{Header: header, Rows: rows})
	_ = m.Build()
	return buf.String()
}

func buildBulletListString(items []string) string {
	var buf strings.Builder
	m := md.NewMarkdown(&buf)
	m.BulletList(items...)
	_ = m.Build()
	return buf.String()
}

// deepLinkEntry holds a single deep link extracted from intent-filter data specs.
type deepLinkEntry struct {
	component string
	uri       string
	actions   string
}

// collectDeepLinks extracts deep link URI patterns from exported component
// intent-filters. Each DataSpec with a non-empty scheme or host produces
// one entry.
func collectDeepLinks(components []ExportedComponent) []deepLinkEntry {
	var links []deepLinkEntry
	for _, ec := range components {
		for _, f := range ec.IntentFilters {
			for _, d := range f.Data {
				if d.Scheme == "" && d.Host == "" {
					continue
				}
				uri := d.Scheme + "://"
				if d.Host != "" {
					uri += d.Host
				}
				if d.Path != "" {
					uri += d.Path
				}
				links = append(links, deepLinkEntry{
					component: ec.Name,
					uri:       uri,
					actions:   strings.Join(f.Actions, ", "),
				})
			}
		}
	}
	return links
}

func buildSigningTable(signing *SigningInfo) string {
	rows := make([][]string, 0, len(signing.Certificates))
	for _, c := range signing.Certificates {
		fp := c.SHA256Fingerprint
		if len(fp) > 16 {
			fp = fp[:16] + "..."
		}
		rows = append(rows, []string{c.Subject, c.Issuer, c.NotAfter, fp})
	}
	return buildTableString([]string{"Subject", "Issuer", "Expires", "Fingerprint"}, rows)
}
