package mobilepkg_test

import (
	"bytes"
	"context"
	"fmt"
	"log"

	"github.com/nao1215/mobilepkg"
)

// ExampleCompare demonstrates comparing two inspect results.
func ExampleCompare() {
	oldResult := &mobilepkg.InspectResult{
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
	newResult := &mobilepkg.InspectResult{
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

	diff := mobilepkg.Compare(oldResult, newResult)
	fmt.Println("Identity changed:", diff.IdentityChanged)
	fmt.Println("Version changed:", diff.VersionChanged)
	// Output:
	// Identity changed: false
	// Version changed: true
}

// ExampleCompare_permissions demonstrates detecting permission changes.
func ExampleCompare_permissions() {
	oldResult := &mobilepkg.InspectResult{
		Permissions: []mobilepkg.Permission{
			{Canonical: "camera", RawName: "android.permission.CAMERA", Source: "manifest"},
			{Canonical: "network", RawName: "android.permission.INTERNET", Source: "manifest"},
		},
	}
	newResult := &mobilepkg.InspectResult{
		Permissions: []mobilepkg.Permission{
			{Canonical: "camera", RawName: "android.permission.CAMERA", Source: "manifest"},
			{Canonical: "location", RawName: "android.permission.ACCESS_FINE_LOCATION", Source: "manifest"},
		},
	}

	diff := mobilepkg.Compare(oldResult, newResult)
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

// ExampleNewReportFile demonstrates creating a report.json output.
func ExampleNewReportFile() {
	ar := &mobilepkg.InspectResult{
		Platform: mobilepkg.PlatformAndroid,
		Format:   mobilepkg.FormatAPK,
		Identity: mobilepkg.Identity{Identifier: "com.example.app"},
	}
	rf := mobilepkg.NewReportFile(ar, "1.0.0")

	var buf bytes.Buffer
	if err := mobilepkg.WriteReportJSON(&buf, rf); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Schema:", rf.SchemaVersion)
	fmt.Println("Tool:", rf.ToolVersion)
	// Output:
	// Schema: 1.0.0
	// Tool: 1.0.0
}

// ExampleEvaluateFailConditions demonstrates CI fail condition evaluation.
func ExampleEvaluateFailConditions() {
	ar := &mobilepkg.InspectResult{
		Findings: []mobilepkg.Finding{
			{
				ID:         "manifest.debuggable",
				Severity:   mobilepkg.SeverityError,
				Confidence: mobilepkg.ConfidenceHigh,
				Message:    "application is debuggable",
			},
		},
	}

	result := mobilepkg.EvaluateFailConditions(ar, mobilepkg.DefaultFailPolicy(), nil)
	fmt.Println("Passed:", result.Passed)
	fmt.Println("Reasons:", len(result.Reasons))
	// Output:
	// Passed: false
	// Reasons: 1
}

// ExampleInspectFile demonstrates the primary inspection path.
func ExampleInspectFile() {
	// For demonstration, we show the API shape. In real usage, provide
	// a valid APK/IPA path:
	//
	//   result, err := mobilepkg.InspectFile(ctx, "app.apk")
	//   if err != nil {
	//       log.Fatal(err)
	//   }
	//   fmt.Println(result.Identity.Identifier)
	//   for _, f := range result.Findings {
	//       fmt.Printf("[%s] %s\n", f.Severity, f.Message)
	//   }
	_ = context.Background()

	// Construct a result manually for the example output.
	result := &mobilepkg.InspectResult{
		Platform: mobilepkg.PlatformAndroid,
		Format:   mobilepkg.FormatAPK,
		Identity: mobilepkg.Identity{
			Identifier:  "com.example.helloworld",
			DisplayName: "HelloWorld",
		},
		Version: mobilepkg.Version{Marketing: "1.0", Build: "1"},
		Entry:   mobilepkg.EntryPoint{Kind: "activity", Name: "com.example.helloworld.MainActivity"},
	}

	fmt.Println("Platform:", result.Platform)
	fmt.Println("ID:", result.Identity.Identifier)
	fmt.Println("Name:", result.Identity.DisplayName)
	fmt.Println("Version:", result.Version.Marketing)
	fmt.Println("Entry:", result.Entry.Kind, result.Entry.Name)
	// Output:
	// Platform: android
	// ID: com.example.helloworld
	// Name: HelloWorld
	// Version: 1.0
	// Entry: activity com.example.helloworld.MainActivity
}
