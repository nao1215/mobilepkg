package mobilepkg

import (
	"errors"
	"fmt"
	"regexp"
)

// Rule defines an inspection rule that checks an [InspectResult] for violations.
// Implementations should be stateless and safe for concurrent use.
type Rule interface {
	Validate(result *InspectResult) []Violation
}

// RuleFunc is an adapter that allows ordinary functions to be used as [Rule]s.
type RuleFunc func(*InspectResult) []Violation

// Validate implements the [Rule] interface.
func (f RuleFunc) Validate(result *InspectResult) []Violation {
	return f(result)
}

// Violation represents a single rule violation found during validation.
type Violation struct {
	// RuleID is the machine-readable identifier of the rule that produced
	// this violation (e.g. "required_field", "permission_denied").
	RuleID string `json:"rule_id"`
	// Severity classifies the importance of the violation.
	Severity Severity `json:"severity"`
	// Message is a human-readable description of the violation.
	Message string `json:"message"`
	// Field identifies the report field related to the violation
	// (e.g. "Identity.Identifier", "Permissions[2].RawName").
	Field string `json:"field"`
}

// Validate applies every rule in rules to the result and collects
// all resulting violations into a single slice. Rules are evaluated in order.
func Validate(result *InspectResult, rules []Rule) []Violation {
	violations := make([]Violation, 0, len(rules))
	for _, r := range rules {
		violations = append(violations, r.Validate(result)...)
	}
	return violations
}

// ErrUnknownField is returned by [RequireFields] when an unrecognized
// field name is provided. This fail-closed behavior prevents silent
// misconfiguration.
var ErrUnknownField = errors.New("mobilepkg: unknown field name")

// RequireFields returns a [Rule] that checks whether the named fields
// are populated (non-empty) in the report. Supported field names:
//
//   - "identifier"          — Identity.Identifier
//   - "display_name"        — Identity.DisplayName
//   - "version_marketing"   — Version.Marketing
//   - "version_build"       — Version.Build
//   - "min_sdk"             — SDK.MinSDK
//   - "target_sdk"          — SDK.TargetSDK
//   - "entry_name"          — Entry.Name
//
// An error wrapping [ErrUnknownField] is returned if any field name is
// not recognized. This fail-closed behavior prevents silent misconfiguration.
func RequireFields(fields ...string) (Rule, error) {
	for _, name := range fields {
		field, _ := resolveField(&InspectResult{}, name)
		if field == "" {
			return nil, fmt.Errorf("%w: %q", ErrUnknownField, name)
		}
	}
	return &requireFieldsRule{fields: fields}, nil
}

type requireFieldsRule struct {
	fields []string
}

func (r *requireFieldsRule) Validate(result *InspectResult) []Violation {
	var violations []Violation
	for _, name := range r.fields {
		field, value := resolveField(result, name)
		if field == "" {
			// This should not happen because RequireFields validates
			// field names upfront, but handle defensively.
			violations = append(violations, Violation{
				RuleID:   "unknown_field",
				Severity: SeverityError,
				Message:  fmt.Sprintf("unknown field name %q", name),
				Field:    name,
			})
			continue
		}
		if value == "" {
			violations = append(violations, Violation{
				RuleID:   "required_field",
				Severity: SeverityError,
				Message:  fmt.Sprintf("required field %q is empty", name),
				Field:    field,
			})
		}
	}
	return violations
}

// resolveField maps a friendly field name to its InspectResult path and current value.
func resolveField(result *InspectResult, name string) (field, value string) {
	switch name {
	case "identifier":
		return "Identity.Identifier", result.Identity.Identifier
	case "display_name":
		return "Identity.DisplayName", result.Identity.DisplayName
	case "version_marketing":
		return "Version.Marketing", result.Version.Marketing
	case "version_build":
		return "Version.Build", result.Version.Build
	case "min_sdk":
		return "SDK.MinSDK", result.SDK.MinSDK
	case "target_sdk":
		return "SDK.TargetSDK", result.SDK.TargetSDK
	case "entry_name":
		return "Entry.Name", result.Entry.Name
	default:
		return "", ""
	}
}

// PermissionAllowList returns a [Rule] that reports a violation for every
// permission whose [Permission.RawName] is not in the allowed set.
func PermissionAllowList(allowed ...string) Rule {
	set := make(map[string]struct{}, len(allowed))
	for _, p := range allowed {
		set[p] = struct{}{}
	}
	return &permissionAllowListRule{allowed: set}
}

type permissionAllowListRule struct {
	allowed map[string]struct{}
}

func (r *permissionAllowListRule) Validate(result *InspectResult) []Violation {
	var violations []Violation
	for i, p := range result.Permissions {
		if _, ok := r.allowed[p.RawName]; !ok {
			violations = append(violations, Violation{
				RuleID:   "permission_not_allowed",
				Severity: SeverityWarn,
				Message:  fmt.Sprintf("permission %q is not in the allow list", p.RawName),
				Field:    fmt.Sprintf("Permissions[%d].RawName", i),
			})
		}
	}
	return violations
}

// PermissionDenyList returns a [Rule] that reports a violation for every
// permission whose [Permission.RawName] is in the denied set.
func PermissionDenyList(denied ...string) Rule {
	set := make(map[string]struct{}, len(denied))
	for _, p := range denied {
		set[p] = struct{}{}
	}
	return &permissionDenyListRule{denied: set}
}

type permissionDenyListRule struct {
	denied map[string]struct{}
}

func (r *permissionDenyListRule) Validate(result *InspectResult) []Violation {
	var violations []Violation
	for i, p := range result.Permissions {
		if _, ok := r.denied[p.RawName]; ok {
			violations = append(violations, Violation{
				RuleID:   "permission_denied",
				Severity: SeverityError,
				Message:  fmt.Sprintf("permission %q is in the deny list", p.RawName),
				Field:    fmt.Sprintf("Permissions[%d].RawName", i),
			})
		}
	}
	return violations
}

// VersionFormat returns a [Rule] that checks whether the marketing version
// string matches the given regular expression pattern. An empty marketing
// version is not checked (use [RequireFields] for that).
func VersionFormat(pattern string) Rule {
	re := regexp.MustCompile(pattern)
	return &versionFormatRule{re: re}
}

type versionFormatRule struct {
	re *regexp.Regexp
}

func (r *versionFormatRule) Validate(result *InspectResult) []Violation {
	v := result.Version.Marketing
	if v == "" {
		return nil
	}
	if !r.re.MatchString(v) {
		return []Violation{{
			RuleID:   "version_format",
			Severity: SeverityError,
			Message:  fmt.Sprintf("version %q does not match pattern %q", v, r.re.String()),
			Field:    "Version.Marketing",
		}}
	}
	return nil
}
