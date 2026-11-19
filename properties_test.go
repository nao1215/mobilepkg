package mobilepkg_test

// Generated properties and metamorphic relations for the parts of the public
// API that compute verdicts and differences from already-extracted results:
// Check / EvaluateFailConditions, Compare and the report.json
// round trip. The example-based tests pin specific cases; these check that the
// rules hold for any combination of findings, permissions, components and
// endpoints that rapid generates. A failure prints the seed to replay it.

import (
	"bytes"
	"slices"
	"testing"

	"pgregory.net/rapid"

	"github.com/nao1215/mobilepkg"
)

var (
	propSeverities  = []mobilepkg.Severity{mobilepkg.SeverityInfo, mobilepkg.SeverityWarn, mobilepkg.SeverityError}
	propConfidences = []mobilepkg.Confidence{mobilepkg.ConfidenceLow, mobilepkg.ConfidenceMedium, mobilepkg.ConfidenceHigh}
)

// A small alphabet makes collisions (same ID, same fingerprint, same
// permission name) frequent, which is where set-based diffs go wrong.
func genToken() *rapid.Generator[string] {
	return rapid.SampledFrom([]string{"a", "b", "c", "d", "e"})
}

func genFinding() *rapid.Generator[mobilepkg.Finding] {
	return rapid.Custom(func(t *rapid.T) mobilepkg.Finding {
		return mobilepkg.Finding{
			ID:          "id." + genToken().Draw(t, "id"),
			Category:    rapid.SampledFrom([]string{"permission", "secret", "endpoint"}).Draw(t, "category"),
			Severity:    rapid.SampledFrom(propSeverities).Draw(t, "severity"),
			Confidence:  rapid.SampledFrom(propConfidences).Draw(t, "confidence"),
			Message:     rapid.String().Draw(t, "message"),
			Fingerprint: "fp." + genToken().Draw(t, "fingerprint"),
			Evidence: []mobilepkg.Evidence{{
				ArchivePath: rapid.String().Draw(t, "archive_path"),
				Line:        rapid.IntRange(0, 1000).Draw(t, "line"),
			}},
		}
	})
}

func genFindings() *rapid.Generator[[]mobilepkg.Finding] {
	return rapid.SliceOfN(genFinding(), 0, 12)
}

func genPolicy() *rapid.Generator[mobilepkg.FailPolicy] {
	return rapid.Custom(func(t *rapid.T) mobilepkg.FailPolicy {
		return mobilepkg.FailPolicy{
			FailOnSeverity:   rapid.SampledFrom(append([]mobilepkg.Severity{""}, propSeverities...)).Draw(t, "fail_on_severity"),
			FailOnConfidence: rapid.SampledFrom(append([]mobilepkg.Confidence{""}, propConfidences...)).Draw(t, "fail_on_confidence"),
		}
	})
}

func genResult() *rapid.Generator[*mobilepkg.InspectResult] {
	return rapid.Custom(func(t *rapid.T) *mobilepkg.InspectResult {
		perm := rapid.Custom(func(t *rapid.T) mobilepkg.Permission {
			return mobilepkg.Permission{
				RawName: "android.permission." + genToken().Draw(t, "raw"),
				Source:  "manifest",
			}
		})
		comp := rapid.Custom(func(t *rapid.T) mobilepkg.ExportedComponent {
			return mobilepkg.ExportedComponent{
				Kind:     rapid.SampledFrom([]string{"activity", "service", "receiver", "provider"}).Draw(t, "kind"),
				Name:     "com.example." + genToken().Draw(t, "name"),
				Exported: true,
			}
		})
		endpoint := rapid.Custom(func(t *rapid.T) mobilepkg.NetworkEndpoint {
			return mobilepkg.NetworkEndpoint{
				Scheme:     rapid.SampledFrom([]string{"http", "https"}).Draw(t, "scheme"),
				Host:       genToken().Draw(t, "host") + ".example",
				Source:     "manifest",
				Confidence: rapid.SampledFrom(propConfidences).Draw(t, "endpoint_confidence"),
			}
		})
		return &mobilepkg.InspectResult{
			Platform:           mobilepkg.PlatformAndroid,
			Format:             mobilepkg.FormatAPK,
			Identity:           mobilepkg.Identity{Identifier: "com.example." + genToken().Draw(t, "identity")},
			Version:            mobilepkg.Version{Marketing: genToken().Draw(t, "version")},
			Permissions:        rapid.SliceOfN(perm, 0, 6).Draw(t, "permissions"),
			ExportedComponents: rapid.SliceOfN(comp, 0, 6).Draw(t, "components"),
			NetworkEndpoints:   rapid.SliceOfN(endpoint, 0, 6).Draw(t, "endpoints"),
			Findings:           genFindings().Draw(t, "findings"),
		}
	})
}

func findingKeys(fs []mobilepkg.Finding) []string {
	keys := make([]string, 0, len(fs))
	for _, f := range fs {
		keys = append(keys, f.ID+"\x00"+f.Fingerprint)
	}
	slices.Sort(keys)
	return keys
}

// The verdict depends on which findings exist, not on the order the
// analysis happened to emit them.
func TestCheck_VerdictDoesNotDependOnFindingOrder(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		findings := genFindings().Draw(t, "findings")
		policy := genPolicy().Draw(t, "policy")
		shuffled := rapid.Permutation(findings).Draw(t, "shuffled")

		got := mobilepkg.Check(&mobilepkg.InspectResult{Findings: findings}, policy)
		gotShuffled := mobilepkg.Check(&mobilepkg.InspectResult{Findings: shuffled}, policy)

		if got.Passed != gotShuffled.Passed {
			t.Fatalf("Passed changed with order: %v vs %v", got.Passed, gotShuffled.Passed)
		}
		if !slices.Equal(findingKeys(got.TriggeringFindings), findingKeys(gotShuffled.TriggeringFindings)) {
			t.Fatalf("triggering findings changed with order")
		}
	})
}

// Adding a finding can only make a passing result fail, never the reverse.
func TestCheck_AddingAFindingNeverTurnsAFailIntoAPass(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		findings := genFindings().Draw(t, "findings")
		extra := genFinding().Draw(t, "extra")
		policy := genPolicy().Draw(t, "policy")

		before := mobilepkg.Check(&mobilepkg.InspectResult{Findings: findings}, policy)
		after := mobilepkg.Check(&mobilepkg.InspectResult{Findings: append(slices.Clone(findings), extra)}, policy)

		if !before.Passed && after.Passed {
			t.Fatalf("adding %+v turned a failing result into a passing one", extra)
		}
		if len(after.TriggeringFindings) < len(before.TriggeringFindings) {
			t.Fatalf("triggering findings shrank from %d to %d", len(before.TriggeringFindings), len(after.TriggeringFindings))
		}
	})
}

// A lower severity threshold is stricter: everything that fails at warn
// also fails at info.
func TestCheck_LoweringTheSeverityThresholdKeepsEveryTrigger(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		findings := genFindings().Draw(t, "findings")
		hi := rapid.IntRange(0, len(propSeverities)-1).Draw(t, "high")
		lo := rapid.IntRange(0, hi).Draw(t, "low")
		ir := &mobilepkg.InspectResult{Findings: findings}

		loose := mobilepkg.Check(ir, mobilepkg.FailPolicy{FailOnSeverity: propSeverities[hi]})
		strict := mobilepkg.Check(ir, mobilepkg.FailPolicy{FailOnSeverity: propSeverities[lo]})

		looseKeys := findingKeys(loose.TriggeringFindings)
		strictKeys := findingKeys(strict.TriggeringFindings)
		for _, k := range looseKeys {
			if !slices.Contains(strictKeys, k) {
				t.Fatalf("finding %q fails at %s but not at %s", k, propSeverities[hi], propSeverities[lo])
			}
		}
		if !loose.Passed && strict.Passed {
			t.Fatalf("%s fails but the stricter %s passes", propSeverities[hi], propSeverities[lo])
		}
	})
}

// Every triggering finding is one of the inspected findings and meets the
// threshold; every finding that meets the threshold triggers.
func TestCheck_TriggersExactlyTheFindingsAtOrAboveTheThreshold(t *testing.T) {
	t.Parallel()
	rank := map[mobilepkg.Severity]int{mobilepkg.SeverityInfo: 0, mobilepkg.SeverityWarn: 1, mobilepkg.SeverityError: 2}
	rapid.Check(t, func(t *rapid.T) {
		findings := genFindings().Draw(t, "findings")
		threshold := rapid.SampledFrom(propSeverities).Draw(t, "threshold")

		got := mobilepkg.Check(&mobilepkg.InspectResult{Findings: findings}, mobilepkg.FailPolicy{FailOnSeverity: threshold})

		var want []mobilepkg.Finding
		for _, f := range findings {
			if rank[f.Severity] >= rank[threshold] {
				want = append(want, f)
			}
		}
		if !slices.Equal(findingKeys(got.TriggeringFindings), findingKeys(want)) {
			t.Fatalf("triggering %v, want %v", findingKeys(got.TriggeringFindings), findingKeys(want))
		}
		if got.Passed != (len(want) == 0) {
			t.Fatalf("Passed = %v with %d qualifying findings", got.Passed, len(want))
		}
		if len(got.Reasons) != len(got.TriggeringFindings) {
			t.Fatalf("%d reasons for %d triggering findings", len(got.Reasons), len(got.TriggeringFindings))
		}
	})
}

// With NewOnly, comparing a result against itself finds nothing new.
func TestEvaluateFailConditions_NewOnlyAgainstItselfAlwaysPasses(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		ir := &mobilepkg.InspectResult{Findings: genFindings().Draw(t, "findings")}
		policy := genPolicy().Draw(t, "policy")
		policy.NewOnly = true

		got := mobilepkg.EvaluateFailConditions(ir, policy, ir)
		if !got.Passed {
			t.Fatalf("NewOnly against the same result failed: %v", got.Reasons)
		}
	})
}

// Compare of a result with itself reports no change at all.
func TestCompare_ResultWithItselfHasNoChanges(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		ir := genResult().Draw(t, "result")
		d := mobilepkg.Compare(ir, ir)
		if d.IdentityChanged || d.VersionChanged || d.EntryChanged {
			t.Fatalf("self compare reports a change: %+v", d)
		}
		if len(d.AddedPermissions)+len(d.RemovedPermissions)+len(d.AddedComponents)+
			len(d.RemovedComponents)+len(d.AddedEndpoints)+len(d.RemovedEndpoints) != 0 {
			t.Fatalf("self compare lists differences: %+v", d)
		}
	})
}

// Compare(old, new) and Compare(new, old) describe the same change from
// opposite sides.
func TestCompare_SwappingArgumentsSwapsAddedAndRemoved(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := genResult().Draw(t, "a")
		b := genResult().Draw(t, "b")
		ab := mobilepkg.Compare(a, b)
		ba := mobilepkg.Compare(b, a)

		if ab.IdentityChanged != ba.IdentityChanged || ab.VersionChanged != ba.VersionChanged || ab.EntryChanged != ba.EntryChanged {
			t.Fatalf("change flags are not symmetric: %+v vs %+v", ab, ba)
		}
		if !slices.Equal(ab.AddedPermissions, ba.RemovedPermissions) || !slices.Equal(ab.RemovedPermissions, ba.AddedPermissions) {
			t.Fatalf("permission diff is not symmetric")
		}
		if !slices.EqualFunc(ab.AddedComponents, ba.RemovedComponents, sameComponent) ||
			!slices.EqualFunc(ab.RemovedComponents, ba.AddedComponents, sameComponent) {
			t.Fatalf("component diff is not symmetric")
		}
		if !slices.Equal(ab.AddedEndpoints, ba.RemovedEndpoints) || !slices.Equal(ab.RemovedEndpoints, ba.AddedEndpoints) {
			t.Fatalf("endpoint diff is not symmetric")
		}
	})
}

func sameComponent(x, y mobilepkg.ExportedComponent) bool {
	return x.Kind == y.Kind && x.Name == y.Name
}

// Writing a report, loading it back and writing it again gives the same
// bytes, so a baseline saved by one run reads back as the same result.
func TestReportFile_WriteLoadWriteIsStable(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		ir := genResult().Draw(t, "result")
		rf := mobilepkg.NewReportFile(ir, "v0.0.0-test")

		var first bytes.Buffer
		if err := mobilepkg.WriteReportJSON(&first, rf); err != nil {
			t.Fatalf("WriteReportJSON: %v", err)
		}
		loaded, err := mobilepkg.LoadReportFile(bytes.NewReader(first.Bytes()))
		if err != nil {
			t.Fatalf("LoadReportFile: %v", err)
		}
		var second bytes.Buffer
		if err := mobilepkg.WriteReportJSON(&second, loaded); err != nil {
			t.Fatalf("WriteReportJSON (second): %v", err)
		}
		if !bytes.Equal(first.Bytes(), second.Bytes()) {
			t.Fatalf("report changed after a round trip:\n%s\n---\n%s", first.String(), second.String())
		}
		if !slices.Equal(findingKeys(loaded.Result.Findings), findingKeys(ir.Findings)) {
			t.Fatalf("findings changed after a round trip")
		}
	})
}
