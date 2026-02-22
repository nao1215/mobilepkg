package mobilepkg_test

import (
	"context"
	"fmt"
	"log"
	"sort"

	"github.com/nao1215/mobilepkg"
)

func ExampleProbeFile() {
	result, err := mobilepkg.ProbeFile("doc/androidbinary/apk/testdata/helloworld.apk")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Platform:", result.Platform)
	fmt.Println("Format:", result.Format)
	fmt.Println("Container:", result.Container)
	// Output:
	// Platform: android
	// Format: apk
	// Container: zip
}

func ExampleInspectFile() {
	report, err := mobilepkg.InspectFile(
		context.Background(),
		"doc/androidbinary/apk/testdata/helloworld.apk",
		mobilepkg.InspectOptions{},
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Platform:", report.Platform)
	fmt.Println("Format:", report.Format)
	fmt.Println("ID:", report.Identity.Identifier)
	fmt.Println("Name:", report.Identity.DisplayName)
	fmt.Println("Version:", report.Version.Marketing)
	fmt.Println("Build:", report.Version.Build)
	fmt.Println("Entry:", report.Entry.Kind, report.Entry.Name)
	// Output:
	// Platform: android
	// Format: apk
	// ID: com.example.helloworld
	// Name: HelloWorld
	// Version: 1.0
	// Build: 1
	// Entry: activity com.example.helloworld.MainActivity
}

func ExampleInspectFile_sections() {
	report, err := mobilepkg.InspectFile(
		context.Background(),
		"doc/androidbinary/apk/testdata/helloworld.apk",
		mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionIdentity | mobilepkg.SectionVersion,
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("ID:", report.Identity.Identifier)
	fmt.Println("Version:", report.Version.Marketing)
	// Entry was not requested, so it remains empty.
	fmt.Println("Entry:", report.Entry.Name)
	// Output:
	// ID: com.example.helloworld
	// Version: 1.0
	// Entry:
}

func ExampleInspectFile_icon() {
	report, err := mobilepkg.InspectFile(
		context.Background(),
		"doc/androidbinary/apk/testdata/helloworld.apk",
		mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionIcon,
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	if report.Icon != nil {
		fmt.Printf("Icon: %s %dx%d (%d bytes)\n",
			report.Icon.Format, report.Icon.Width, report.Icon.Height, len(report.Icon.Bytes))
	}
	// Output:
	// Icon: png 48x48 (1956 bytes)
}

func ExampleInspectFile_permissions() {
	report, err := mobilepkg.InspectFile(
		context.Background(),
		"doc/androidbinary/apk/testdata/helloworld.apk",
		mobilepkg.InspectOptions{
			Sections: mobilepkg.SectionPermissions,
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Permissions:", len(report.Permissions))
	for _, p := range report.Permissions {
		if p.Canonical != "" {
			fmt.Printf("  %s → %s\n", p.RawName, p.Canonical)
		}
	}
	// Output:
	// Permissions: 0
}

func ExampleDiffReports() {
	oldReport := mobilepkg.Report{
		Platform: mobilepkg.PlatformAndroid,
		Identity: mobilepkg.Identity{
			Identifier:  "com.example.app",
			DisplayName: "My App",
		},
		Version: mobilepkg.Version{
			Marketing: "1.0.0",
			Build:     "1",
		},
	}
	newReport := mobilepkg.Report{
		Platform: mobilepkg.PlatformAndroid,
		Identity: mobilepkg.Identity{
			Identifier:  "com.example.app",
			DisplayName: "My App",
		},
		Version: mobilepkg.Version{
			Marketing: "2.0.0",
			Build:     "5",
		},
	}

	diff := mobilepkg.DiffReports(oldReport, newReport)
	fmt.Println("Identity changed:", diff.IdentityChanged)
	fmt.Println("Version changed:", diff.VersionChanged)
	// Output:
	// Identity changed: false
	// Version changed: true
}

func ExampleDiffReports_permissions() {
	oldReport := mobilepkg.Report{
		Permissions: []mobilepkg.Permission{
			{Canonical: "camera", RawName: "android.permission.CAMERA", Source: "manifest"},
			{Canonical: "network", RawName: "android.permission.INTERNET", Source: "manifest"},
		},
	}
	newReport := mobilepkg.Report{
		Permissions: []mobilepkg.Permission{
			{Canonical: "camera", RawName: "android.permission.CAMERA", Source: "manifest"},
			{Canonical: "location", RawName: "android.permission.ACCESS_FINE_LOCATION", Source: "manifest"},
		},
	}

	diff := mobilepkg.DiffReports(oldReport, newReport)

	// Sort for deterministic output.
	sort.Slice(diff.AddedPermissions, func(i, j int) bool {
		return diff.AddedPermissions[i].RawName < diff.AddedPermissions[j].RawName
	})
	sort.Slice(diff.RemovedPermissions, func(i, j int) bool {
		return diff.RemovedPermissions[i].RawName < diff.RemovedPermissions[j].RawName
	})

	for _, p := range diff.AddedPermissions {
		fmt.Printf("+ %s (%s)\n", p.Canonical, p.RawName)
	}
	for _, p := range diff.RemovedPermissions {
		fmt.Printf("- %s (%s)\n", p.Canonical, p.RawName)
	}
	// Output:
	// + location (android.permission.ACCESS_FINE_LOCATION)
	// - network (android.permission.INTERNET)
}

func ExampleAsAndroid() {
	report := mobilepkg.Report{
		Platform: mobilepkg.PlatformAndroid,
		PlatformData: &mobilepkg.AndroidReport{
			RawManifest: map[string]any{
				"package":     "com.example.app",
				"versionCode": "42",
			},
		},
	}

	ar, ok := mobilepkg.AsAndroid(report)
	if ok {
		fmt.Println("Package:", ar.RawManifest["package"])
		fmt.Println("VersionCode:", ar.RawManifest["versionCode"])
	}
	// Output:
	// Package: com.example.app
	// VersionCode: 42
}

func ExampleAsIOS() {
	report := mobilepkg.Report{
		Platform: mobilepkg.PlatformIOS,
		PlatformData: &mobilepkg.IOSReport{
			InfoPlist: map[string]any{
				"CFBundleIdentifier":  "com.example.app",
				"CFBundleDisplayName": "My App",
			},
			Entitlements: map[string]any{
				"com.apple.developer.healthkit": true,
			},
		},
	}

	ir, ok := mobilepkg.AsIOS(report)
	if ok {
		fmt.Println("BundleID:", ir.InfoPlist["CFBundleIdentifier"])
		fmt.Println("HealthKit:", ir.Entitlements["com.apple.developer.healthkit"])
	}
	// Output:
	// BundleID: com.example.app
	// HealthKit: true
}
