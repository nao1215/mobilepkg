package mobilepkg

import "sort"

// Compare compares two [InspectResult] values and returns a [Diff]
// describing what changed between them.
//
// This is useful for release-diff scenarios where a release manager
// wants to detect added/removed permissions, version bumps, exported
// component changes, or new network endpoints between two builds.
func Compare(oldIR, newIR *InspectResult) Diff {
	oldR := inspectResultToReport(oldIR)
	newR := inspectResultToReport(newIR)
	return diffReports(oldR, newR)
}

// diffReports compares two [report] values and returns a [Diff]
// describing what changed between them. This is the internal
// implementation used by [Compare] and [analyzeReport].
func diffReports(oldR, newR report) Diff {
	d := Diff{
		OldPlatform: oldR.Platform,
		NewPlatform: newR.Platform,
	}

	d.IdentityChanged = oldR.Identity != newR.Identity
	d.VersionChanged = oldR.Version != newR.Version
	d.EntryChanged = oldR.Entry != newR.Entry

	// Permissions diff.
	d.AddedPermissions, d.RemovedPermissions = diffPermissions(oldR.Permissions, newR.Permissions)

	// Exported components diff.
	d.AddedComponents, d.RemovedComponents = diffComponents(oldR.ExportedComponents, newR.ExportedComponents)

	// Network endpoints diff.
	d.AddedEndpoints, d.RemovedEndpoints = diffEndpoints(oldR.NetworkEndpoints, newR.NetworkEndpoints)

	return d
}

func diffPermissions(oldPerms, newPerms []Permission) (added, removed []Permission) {
	oldSet := make(map[string]Permission, len(oldPerms))
	for _, p := range oldPerms {
		oldSet[p.RawName] = p
	}
	newSet := make(map[string]Permission, len(newPerms))
	for _, p := range newPerms {
		newSet[p.RawName] = p
	}
	for raw, p := range newSet {
		if _, exists := oldSet[raw]; !exists {
			added = append(added, p)
		}
	}
	for raw, p := range oldSet {
		if _, exists := newSet[raw]; !exists {
			removed = append(removed, p)
		}
	}
	sort.Slice(added, func(i, j int) bool { return added[i].RawName < added[j].RawName })
	sort.Slice(removed, func(i, j int) bool { return removed[i].RawName < removed[j].RawName })
	return added, removed
}

func diffComponents(oldComps, newComps []ExportedComponent) (added, removed []ExportedComponent) {
	key := func(c ExportedComponent) string { return c.Kind + "\x00" + c.Name }
	oldSet := make(map[string]ExportedComponent, len(oldComps))
	for _, c := range oldComps {
		oldSet[key(c)] = c
	}
	newSet := make(map[string]ExportedComponent, len(newComps))
	for _, c := range newComps {
		newSet[key(c)] = c
	}
	for k, c := range newSet {
		if _, exists := oldSet[k]; !exists {
			added = append(added, c)
		}
	}
	for k, c := range oldSet {
		if _, exists := newSet[k]; !exists {
			removed = append(removed, c)
		}
	}
	sort.Slice(added, func(i, j int) bool { return added[i].Name < added[j].Name })
	sort.Slice(removed, func(i, j int) bool { return removed[i].Name < removed[j].Name })
	return added, removed
}

func diffEndpoints(oldEPs, newEPs []NetworkEndpoint) (added, removed []NetworkEndpoint) {
	key := func(e NetworkEndpoint) string { return e.Scheme + "://" + e.Host + e.Path }
	oldSet := make(map[string]NetworkEndpoint, len(oldEPs))
	for _, e := range oldEPs {
		oldSet[key(e)] = e
	}
	newSet := make(map[string]NetworkEndpoint, len(newEPs))
	for _, e := range newEPs {
		newSet[key(e)] = e
	}
	for k, e := range newSet {
		if _, exists := oldSet[k]; !exists {
			added = append(added, e)
		}
	}
	for k, e := range oldSet {
		if _, exists := newSet[k]; !exists {
			removed = append(removed, e)
		}
	}
	sort.Slice(added, func(i, j int) bool { return added[i].Host < added[j].Host })
	sort.Slice(removed, func(i, j int) bool { return removed[i].Host < removed[j].Host })
	return added, removed
}
