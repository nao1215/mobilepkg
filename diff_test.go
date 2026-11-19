package mobilepkg_test

import (
	"testing"

	"github.com/nao1215/mobilepkg"
)

func TestDiffReports(t *testing.T) {
	t.Parallel()

	t.Run("detects no changes for identical reports", func(t *testing.T) {
		t.Parallel()
		report := mobilepkg.InspectResult{
			Platform: mobilepkg.PlatformAndroid,
			Identity: mobilepkg.Identity{
				Identifier:  "com.example.app",
				DisplayName: "My App",
			},
			Version: mobilepkg.Version{
				Marketing: "1.0.0",
				Build:     "1",
			},
			Permissions: []mobilepkg.Permission{
				{RawName: "android.permission.CAMERA", Source: "manifest"},
			},
		}

		diff := mobilepkg.Compare(&report, &report)
		if diff.IdentityChanged {
			t.Error("IdentityChanged should be false for identical reports")
		}
		if diff.VersionChanged {
			t.Error("VersionChanged should be false for identical reports")
		}
		if diff.EntryChanged {
			t.Error("EntryChanged should be false for identical reports")
		}
		if len(diff.AddedPermissions) != 0 {
			t.Errorf("AddedPermissions = %d, want 0", len(diff.AddedPermissions))
		}
		if len(diff.RemovedPermissions) != 0 {
			t.Errorf("RemovedPermissions = %d, want 0", len(diff.RemovedPermissions))
		}
	})

	t.Run("detects version change", func(t *testing.T) {
		t.Parallel()
		oldReport := mobilepkg.InspectResult{
			Version: mobilepkg.Version{Marketing: "1.0.0", Build: "1"},
		}
		newReport := mobilepkg.InspectResult{
			Version: mobilepkg.Version{Marketing: "2.0.0", Build: "2"},
		}

		diff := mobilepkg.Compare(&oldReport, &newReport)
		if !diff.VersionChanged {
			t.Error("VersionChanged should be true")
		}
	})

	t.Run("detects identity change", func(t *testing.T) {
		t.Parallel()
		oldReport := mobilepkg.InspectResult{
			Identity: mobilepkg.Identity{Identifier: "com.old.app"},
		}
		newReport := mobilepkg.InspectResult{
			Identity: mobilepkg.Identity{Identifier: "com.new.app"},
		}

		diff := mobilepkg.Compare(&oldReport, &newReport)
		if !diff.IdentityChanged {
			t.Error("IdentityChanged should be true")
		}
	})

	t.Run("detects added permissions", func(t *testing.T) {
		t.Parallel()
		oldReport := mobilepkg.InspectResult{
			Permissions: []mobilepkg.Permission{
				{RawName: "android.permission.CAMERA", Source: "manifest"},
			},
		}
		newReport := mobilepkg.InspectResult{
			Permissions: []mobilepkg.Permission{
				{RawName: "android.permission.CAMERA", Source: "manifest"},
				{RawName: "android.permission.INTERNET", Source: "manifest"},
			},
		}

		diff := mobilepkg.Compare(&oldReport, &newReport)
		if len(diff.AddedPermissions) != 1 {
			t.Fatalf("AddedPermissions = %d, want 1", len(diff.AddedPermissions))
		}
		if diff.AddedPermissions[0].RawName != "android.permission.INTERNET" {
			t.Errorf("AddedPermissions[0].RawName = %q, want %q",
				diff.AddedPermissions[0].RawName, "android.permission.INTERNET")
		}
	})

	t.Run("detects removed permissions", func(t *testing.T) {
		t.Parallel()
		oldReport := mobilepkg.InspectResult{
			Permissions: []mobilepkg.Permission{
				{RawName: "android.permission.CAMERA", Source: "manifest"},
				{RawName: "android.permission.INTERNET", Source: "manifest"},
			},
		}
		newReport := mobilepkg.InspectResult{
			Permissions: []mobilepkg.Permission{
				{RawName: "android.permission.CAMERA", Source: "manifest"},
			},
		}

		diff := mobilepkg.Compare(&oldReport, &newReport)
		if len(diff.RemovedPermissions) != 1 {
			t.Fatalf("RemovedPermissions = %d, want 1", len(diff.RemovedPermissions))
		}
		if diff.RemovedPermissions[0].RawName != "android.permission.INTERNET" {
			t.Errorf("RemovedPermissions[0].RawName = %q, want %q",
				diff.RemovedPermissions[0].RawName, "android.permission.INTERNET")
		}
	})

	t.Run("detects entry point change", func(t *testing.T) {
		t.Parallel()
		oldReport := mobilepkg.InspectResult{
			Entry: mobilepkg.EntryPoint{Kind: "activity", Name: "com.app.OldMain"},
		}
		newReport := mobilepkg.InspectResult{
			Entry: mobilepkg.EntryPoint{Kind: "activity", Name: "com.app.NewMain"},
		}

		diff := mobilepkg.Compare(&oldReport, &newReport)
		if !diff.EntryChanged {
			t.Error("EntryChanged should be true")
		}
	})

	t.Run("tracks platform of both reports", func(t *testing.T) {
		t.Parallel()
		oldReport := mobilepkg.InspectResult{Platform: mobilepkg.PlatformAndroid}
		newReport := mobilepkg.InspectResult{Platform: mobilepkg.PlatformIOS}

		diff := mobilepkg.Compare(&oldReport, &newReport)
		if diff.OldPlatform != mobilepkg.PlatformAndroid {
			t.Errorf("OldPlatform = %q, want %q", diff.OldPlatform, mobilepkg.PlatformAndroid)
		}
		if diff.NewPlatform != mobilepkg.PlatformIOS {
			t.Errorf("NewPlatform = %q, want %q", diff.NewPlatform, mobilepkg.PlatformIOS)
		}
	})
}

func TestCompare_ListsComponentsAndEndpointsSharingANameInAFixedOrder(t *testing.T) {
	t.Parallel()

	oldIR := &mobilepkg.InspectResult{Platform: mobilepkg.PlatformAndroid}
	newIR := &mobilepkg.InspectResult{
		Platform: mobilepkg.PlatformAndroid,
		ExportedComponents: []mobilepkg.ExportedComponent{
			{Kind: "service", Name: "com.example.Sync", Exported: true},
			{Kind: "activity", Name: "com.example.Sync", Exported: true},
			{Kind: "receiver", Name: "com.example.Sync", Exported: true},
			{Kind: "provider", Name: "com.example.Sync", Exported: true},
		},
		NetworkEndpoints: []mobilepkg.NetworkEndpoint{
			{Scheme: "https", Host: "api.example.com", Path: "/v2", Source: "manifest"},
			{Scheme: "http", Host: "api.example.com", Source: "manifest"},
			{Scheme: "https", Host: "api.example.com", Source: "manifest"},
			{Scheme: "https", Host: "api.example.com", Path: "/v1", Source: "manifest"},
		},
	}
	wantKinds := []string{"activity", "provider", "receiver", "service"}
	wantEndpoints := []string{
		"http://api.example.com",
		"https://api.example.com",
		"https://api.example.com/v1",
		"https://api.example.com/v2",
	}

	// Map iteration order varies between calls, so a single call can pass
	// by luck; repeat to make an unordered result show up.
	for range 50 {
		d := mobilepkg.Compare(oldIR, newIR)
		for i, c := range d.AddedComponents {
			if c.Kind != wantKinds[i] {
				t.Fatalf("AddedComponents[%d].Kind = %q, want %q (order %v)", i, c.Kind, wantKinds[i], d.AddedComponents)
			}
		}
		for i, e := range d.AddedEndpoints {
			if got := e.Scheme + "://" + e.Host + e.Path; got != wantEndpoints[i] {
				t.Fatalf("AddedEndpoints[%d] = %q, want %q", i, got, wantEndpoints[i])
			}
		}
		rd := mobilepkg.Compare(newIR, oldIR)
		for i, c := range rd.RemovedComponents {
			if c.Kind != wantKinds[i] {
				t.Fatalf("RemovedComponents[%d].Kind = %q, want %q", i, c.Kind, wantKinds[i])
			}
		}
		for i, e := range rd.RemovedEndpoints {
			if got := e.Scheme + "://" + e.Host + e.Path; got != wantEndpoints[i] {
				t.Fatalf("RemovedEndpoints[%d] = %q, want %q", i, got, wantEndpoints[i])
			}
		}
	}
}

func TestDiffFindings_OrdersFindingsSharingAnIDByFingerprint(t *testing.T) {
	t.Parallel()

	current := []mobilepkg.Finding{
		{ID: "secret.api_key", Fingerprint: "c"},
		{ID: "secret.api_key", Fingerprint: "a"},
		{ID: "secret.api_key", Fingerprint: "b"},
	}
	reversed := []mobilepkg.Finding{current[2], current[1], current[0]}

	added, _ := mobilepkg.DiffFindings(nil, current)
	addedReversed, _ := mobilepkg.DiffFindings(nil, reversed)
	for i, want := range []string{"a", "b", "c"} {
		if added[i].Fingerprint != want || addedReversed[i].Fingerprint != want {
			t.Fatalf("added[%d] fingerprints = %q / %q, want %q", i, added[i].Fingerprint, addedReversed[i].Fingerprint, want)
		}
	}
}
