package mobilepkg

import "sort"

// DiffReports compares two [Report] values and returns a [Diff]
// describing what changed between them.
//
// This is useful for release-diff scenarios where a release manager
// wants to detect added/removed permissions, version bumps, or
// entry-point changes between two builds.
func DiffReports(oldR, newR Report) Diff {
	d := Diff{
		OldPlatform: oldR.Platform,
		NewPlatform: newR.Platform,
	}

	d.IdentityChanged = oldR.Identity != newR.Identity
	d.VersionChanged = oldR.Version != newR.Version
	d.EntryChanged = oldR.Entry != newR.Entry

	oldPerms := make(map[string]Permission, len(oldR.Permissions))
	for _, p := range oldR.Permissions {
		oldPerms[p.RawName] = p
	}

	newPerms := make(map[string]Permission, len(newR.Permissions))
	for _, p := range newR.Permissions {
		newPerms[p.RawName] = p
	}

	for raw, p := range newPerms {
		if _, exists := oldPerms[raw]; !exists {
			d.AddedPermissions = append(d.AddedPermissions, p)
		}
	}

	for raw, p := range oldPerms {
		if _, exists := newPerms[raw]; !exists {
			d.RemovedPermissions = append(d.RemovedPermissions, p)
		}
	}

	sort.Slice(d.AddedPermissions, func(i, j int) bool {
		return d.AddedPermissions[i].RawName < d.AddedPermissions[j].RawName
	})
	sort.Slice(d.RemovedPermissions, func(i, j int) bool {
		return d.RemovedPermissions[i].RawName < d.RemovedPermissions[j].RawName
	})

	return d
}
