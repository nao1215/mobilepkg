package mobilepkg_test

import (
	"testing"

	"github.com/nao1215/mobilepkg"
)

// mustRequireFields is a test helper that calls RequireFields and fails the
// test if an error is returned.
func mustRequireFields(t *testing.T, fields ...string) mobilepkg.Rule {
	t.Helper()
	rule, err := mobilepkg.RequireFields(fields...)
	if err != nil {
		t.Fatalf("RequireFields(%v): %v", fields, err)
	}
	return rule
}

func TestRequireFields(t *testing.T) {
	t.Parallel()

	t.Run("no violations when all fields present", func(t *testing.T) {
		t.Parallel()
		report := mobilepkg.InspectResult{
			Identity: mobilepkg.Identity{
				Identifier:  "com.example.app",
				DisplayName: "Example",
			},
			Version: mobilepkg.Version{
				Marketing: "1.0.0",
				Build:     "42",
			},
			SDK: mobilepkg.SDKConstraints{
				MinSDK:    "21",
				TargetSDK: "34",
			},
		}
		vs := mobilepkg.Validate(&report, []mobilepkg.Rule{
			mustRequireFields(t, "identifier", "display_name", "version_marketing", "version_build", "min_sdk", "target_sdk"),
		})
		if len(vs) != 0 {
			t.Errorf("expected 0 violations, got %d: %v", len(vs), vs)
		}
	})

	t.Run("reports missing fields", func(t *testing.T) {
		t.Parallel()
		report := mobilepkg.InspectResult{
			Identity: mobilepkg.Identity{Identifier: "com.example.app"},
		}
		vs := mobilepkg.Validate(&report, []mobilepkg.Rule{
			mustRequireFields(t, "identifier", "display_name", "version_marketing"),
		})
		if len(vs) != 2 {
			t.Fatalf("expected 2 violations, got %d: %v", len(vs), vs)
		}
		if vs[0].RuleID != "required_field" {
			t.Errorf("vs[0].RuleID = %q, want %q", vs[0].RuleID, "required_field")
		}
		if vs[0].Field != "Identity.DisplayName" {
			t.Errorf("vs[0].Field = %q, want %q", vs[0].Field, "Identity.DisplayName")
		}
		if vs[1].Field != "Version.Marketing" {
			t.Errorf("vs[1].Field = %q, want %q", vs[1].Field, "Version.Marketing")
		}
	})

	t.Run("unknown fields return error", func(t *testing.T) {
		t.Parallel()
		_, err := mobilepkg.RequireFields("nonexistent_field")
		if err == nil {
			t.Error("expected error for unknown field, got nil")
		}
	})
}

func TestPermissionAllowList(t *testing.T) {
	t.Parallel()

	t.Run("no violations when all permissions allowed", func(t *testing.T) {
		t.Parallel()
		report := mobilepkg.InspectResult{
			Permissions: []mobilepkg.Permission{
				{RawName: "android.permission.INTERNET"},
				{RawName: "android.permission.CAMERA"},
			},
		}
		vs := mobilepkg.Validate(&report, []mobilepkg.Rule{
			mobilepkg.PermissionAllowList("android.permission.INTERNET", "android.permission.CAMERA"),
		})
		if len(vs) != 0 {
			t.Errorf("expected 0 violations, got %d: %v", len(vs), vs)
		}
	})

	t.Run("reports permissions not in allow list", func(t *testing.T) {
		t.Parallel()
		report := mobilepkg.InspectResult{
			Permissions: []mobilepkg.Permission{
				{RawName: "android.permission.INTERNET"},
				{RawName: "android.permission.SEND_SMS"},
				{RawName: "android.permission.READ_CONTACTS"},
			},
		}
		vs := mobilepkg.Validate(&report, []mobilepkg.Rule{
			mobilepkg.PermissionAllowList("android.permission.INTERNET"),
		})
		if len(vs) != 2 {
			t.Fatalf("expected 2 violations, got %d: %v", len(vs), vs)
		}
		if vs[0].RuleID != "permission_not_allowed" {
			t.Errorf("vs[0].RuleID = %q, want %q", vs[0].RuleID, "permission_not_allowed")
		}
		if vs[0].Field != "Permissions[1].RawName" {
			t.Errorf("vs[0].Field = %q, want %q", vs[0].Field, "Permissions[1].RawName")
		}
		if vs[1].Field != "Permissions[2].RawName" {
			t.Errorf("vs[1].Field = %q, want %q", vs[1].Field, "Permissions[2].RawName")
		}
	})

	t.Run("no violations when no permissions", func(t *testing.T) {
		t.Parallel()
		report := mobilepkg.InspectResult{}
		vs := mobilepkg.Validate(&report, []mobilepkg.Rule{
			mobilepkg.PermissionAllowList("android.permission.INTERNET"),
		})
		if len(vs) != 0 {
			t.Errorf("expected 0 violations, got %d", len(vs))
		}
	})
}

func TestPermissionDenyList(t *testing.T) {
	t.Parallel()

	t.Run("no violations when no denied permissions present", func(t *testing.T) {
		t.Parallel()
		report := mobilepkg.InspectResult{
			Permissions: []mobilepkg.Permission{
				{RawName: "android.permission.INTERNET"},
			},
		}
		vs := mobilepkg.Validate(&report, []mobilepkg.Rule{
			mobilepkg.PermissionDenyList("android.permission.SEND_SMS"),
		})
		if len(vs) != 0 {
			t.Errorf("expected 0 violations, got %d: %v", len(vs), vs)
		}
	})

	t.Run("reports denied permissions", func(t *testing.T) {
		t.Parallel()
		report := mobilepkg.InspectResult{
			Permissions: []mobilepkg.Permission{
				{RawName: "android.permission.INTERNET"},
				{RawName: "android.permission.SEND_SMS"},
				{RawName: "android.permission.CALL_PHONE"},
			},
		}
		vs := mobilepkg.Validate(&report, []mobilepkg.Rule{
			mobilepkg.PermissionDenyList("android.permission.SEND_SMS", "android.permission.CALL_PHONE"),
		})
		if len(vs) != 2 {
			t.Fatalf("expected 2 violations, got %d: %v", len(vs), vs)
		}
		if vs[0].RuleID != "permission_denied" {
			t.Errorf("vs[0].RuleID = %q, want %q", vs[0].RuleID, "permission_denied")
		}
		if vs[0].Severity != mobilepkg.SeverityError {
			t.Errorf("vs[0].Severity = %q, want %q", vs[0].Severity, mobilepkg.SeverityError)
		}
		if vs[0].Field != "Permissions[1].RawName" {
			t.Errorf("vs[0].Field = %q, want %q", vs[0].Field, "Permissions[1].RawName")
		}
	})
}

func TestVersionFormat(t *testing.T) {
	t.Parallel()

	t.Run("no violation when version matches pattern", func(t *testing.T) {
		t.Parallel()
		report := mobilepkg.InspectResult{
			Version: mobilepkg.Version{Marketing: "1.2.3"},
		}
		vs := mobilepkg.Validate(&report, []mobilepkg.Rule{
			mobilepkg.VersionFormat(`^\d+\.\d+\.\d+$`),
		})
		if len(vs) != 0 {
			t.Errorf("expected 0 violations, got %d: %v", len(vs), vs)
		}
	})

	t.Run("reports violation when version does not match", func(t *testing.T) {
		t.Parallel()
		report := mobilepkg.InspectResult{
			Version: mobilepkg.Version{Marketing: "v1.0-beta"},
		}
		vs := mobilepkg.Validate(&report, []mobilepkg.Rule{
			mobilepkg.VersionFormat(`^\d+\.\d+\.\d+$`),
		})
		if len(vs) != 1 {
			t.Fatalf("expected 1 violation, got %d: %v", len(vs), vs)
		}
		if vs[0].RuleID != "version_format" {
			t.Errorf("RuleID = %q, want %q", vs[0].RuleID, "version_format")
		}
		if vs[0].Field != "Version.Marketing" {
			t.Errorf("Field = %q, want %q", vs[0].Field, "Version.Marketing")
		}
	})

	t.Run("skips check when version is empty", func(t *testing.T) {
		t.Parallel()
		report := mobilepkg.InspectResult{}
		vs := mobilepkg.Validate(&report, []mobilepkg.Rule{
			mobilepkg.VersionFormat(`^\d+\.\d+\.\d+$`),
		})
		if len(vs) != 0 {
			t.Errorf("expected 0 violations for empty version, got %d", len(vs))
		}
	})
}

func TestRuleFunc(t *testing.T) {
	t.Parallel()

	custom := mobilepkg.RuleFunc(func(r *mobilepkg.InspectResult) []mobilepkg.Violation {
		if r.Platform != mobilepkg.PlatformAndroid {
			return []mobilepkg.Violation{{
				RuleID:   "platform_check",
				Severity: mobilepkg.SeverityError,
				Message:  "only Android packages are allowed",
				Field:    "Platform",
			}}
		}
		return nil
	})

	t.Run("custom rule passes", func(t *testing.T) {
		t.Parallel()
		report := mobilepkg.InspectResult{Platform: mobilepkg.PlatformAndroid}
		vs := mobilepkg.Validate(&report, []mobilepkg.Rule{custom})
		if len(vs) != 0 {
			t.Errorf("expected 0 violations, got %d", len(vs))
		}
	})

	t.Run("custom rule fails", func(t *testing.T) {
		t.Parallel()
		report := mobilepkg.InspectResult{Platform: mobilepkg.PlatformIOS}
		vs := mobilepkg.Validate(&report, []mobilepkg.Rule{custom})
		if len(vs) != 1 {
			t.Fatalf("expected 1 violation, got %d", len(vs))
		}
		if vs[0].RuleID != "platform_check" {
			t.Errorf("RuleID = %q, want %q", vs[0].RuleID, "platform_check")
		}
	})
}

func TestValidateReport_MultipleRules(t *testing.T) {
	t.Parallel()

	report := mobilepkg.InspectResult{
		Identity: mobilepkg.Identity{Identifier: "com.example.app"},
		Version:  mobilepkg.Version{Marketing: "bad-version"},
		Permissions: []mobilepkg.Permission{
			{RawName: "android.permission.INTERNET"},
			{RawName: "android.permission.SEND_SMS"},
		},
	}

	rules := []mobilepkg.Rule{
		mustRequireFields(t, "display_name"),
		mobilepkg.VersionFormat(`^\d+\.\d+\.\d+$`),
		mobilepkg.PermissionDenyList("android.permission.SEND_SMS"),
	}

	vs := mobilepkg.Validate(&report, rules)
	if len(vs) != 3 {
		t.Fatalf("expected 3 violations, got %d: %v", len(vs), vs)
	}

	// Verify violations are in rule order
	if vs[0].RuleID != "required_field" {
		t.Errorf("vs[0].RuleID = %q, want %q", vs[0].RuleID, "required_field")
	}
	if vs[1].RuleID != "version_format" {
		t.Errorf("vs[1].RuleID = %q, want %q", vs[1].RuleID, "version_format")
	}
	if vs[2].RuleID != "permission_denied" {
		t.Errorf("vs[2].RuleID = %q, want %q", vs[2].RuleID, "permission_denied")
	}
}

func TestValidateReport_NoRules(t *testing.T) {
	t.Parallel()

	report := mobilepkg.InspectResult{}
	vs := mobilepkg.Validate(&report, nil)
	if len(vs) != 0 {
		t.Errorf("expected 0 violations with nil rules, got %d", len(vs))
	}

	vs = mobilepkg.Validate(&report, []mobilepkg.Rule{})
	if len(vs) != 0 {
		t.Errorf("expected 0 violations with empty rules, got %d", len(vs))
	}
}
