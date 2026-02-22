package mobilepkg

import (
	"errors"
	"fmt"

	"github.com/nao1215/mobilepkg/internal/platform/android"
	"github.com/nao1215/mobilepkg/internal/platform/ios"
)

// Sentinel errors returned by the public API.
// Use [errors.Is] to check for these in wrapped errors.
var (
	// ErrUnsupportedFormat is returned when the file is not a recognized
	// mobile application package (neither APK nor IPA).
	ErrUnsupportedFormat = errors.New("mobilepkg: unsupported package format")
	// ErrManifestMissing is returned when the primary manifest
	// (AndroidManifest.xml or Info.plist) is not found in the archive.
	ErrManifestMissing = errors.New("mobilepkg: primary manifest not found")
	// ErrManifestCorrupt is returned when the primary manifest exists
	// but cannot be parsed.
	ErrManifestCorrupt = errors.New("mobilepkg: primary manifest could not be parsed")
	// ErrArchiveCorrupt is returned when the archive structure is damaged
	// or unreadable beyond the initial ZIP open.
	ErrArchiveCorrupt = errors.New("mobilepkg: archive is corrupt or unreadable")
)

// InspectError is a structured error returned by inspection functions.
// It carries a machine-readable [Code] for programmatic handling and
// supports [errors.Is] / [errors.As] through the wrapped [Err].
type InspectError struct {
	// Code is a machine-readable error code such as "manifest.missing",
	// "manifest.corrupt", "archive.corrupt", or "format.unsupported".
	Code string
	// Message is a human-readable description of the error.
	Message string
	// Err is the underlying cause, if any.
	Err error
}

// Error implements the error interface.
func (e *InspectError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("mobilepkg [%s]: %v", e.Code, e.Err)
	}
	return fmt.Sprintf("mobilepkg [%s]: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error for use with [errors.Is] and [errors.As].
func (e *InspectError) Unwrap() error {
	return e.Err
}

// wrapInspectError wraps err into an [InspectError] with the appropriate
// public sentinel in the error chain so that [errors.Is] works correctly
// with the public sentinel errors (e.g. [ErrManifestCorrupt]).
func wrapInspectError(err error) error {
	var ie *InspectError
	if errors.As(err, &ie) {
		return err
	}

	code, msg, sentinel := classifyError(err)

	if sentinel != nil {
		// Chain: InspectError → sentinel → original err.
		// This ensures errors.Is(result, ErrManifestCorrupt) etc. works.
		return &InspectError{
			Code:    code,
			Message: msg,
			Err:     fmt.Errorf("%w: %w", sentinel, err),
		}
	}
	return &InspectError{Code: code, Message: msg, Err: err}
}

// classifyError maps an internal error to a (code, message, public sentinel) tuple.
func classifyError(err error) (code, message string, sentinel error) {
	switch {
	case errors.Is(err, ErrManifestMissing):
		return "manifest.missing", "primary manifest not found", ErrManifestMissing
	case errors.Is(err, ErrManifestCorrupt):
		return "manifest.corrupt", "primary manifest could not be parsed", ErrManifestCorrupt
	case errors.Is(err, ErrArchiveCorrupt):
		return "archive.corrupt", "archive is corrupt or unreadable", ErrArchiveCorrupt
	case errors.Is(err, ErrUnsupportedFormat):
		return "format.unsupported", "unsupported package format", ErrUnsupportedFormat
	case errors.Is(err, android.ErrManifestNotFound),
		errors.Is(err, ios.ErrInfoPlistNotFound):
		return "manifest.missing", "primary manifest not found", ErrManifestMissing
	case errors.Is(err, android.ErrManifestParseFailed),
		errors.Is(err, ios.ErrInfoPlistParseFailed):
		return "manifest.corrupt", "primary manifest could not be parsed", ErrManifestCorrupt
	default:
		return "unknown", "inspection failed", nil
	}
}

// Severity classifies the importance of a [Diagnostic].
type Severity string

const (
	// SeverityInfo indicates an informational note.
	SeverityInfo Severity = "info"
	// SeverityWarn indicates a potential problem that did not prevent extraction.
	SeverityWarn Severity = "warn"
	// SeverityError indicates a problem that prevented extraction of some data.
	SeverityError Severity = "error"
)

// Diagnostic describes a non-fatal issue encountered during inspection.
type Diagnostic struct {
	// Code is a machine-readable identifier (e.g. "icon.not_found", "plist.parse_failed").
	Code string
	// Severity classifies the importance of the diagnostic.
	Severity Severity
	// Message is a human-readable description.
	Message string
	// Detail carries optional machine-readable metadata associated with
	// the diagnostic (e.g. {"path": "res/icon.png"} for an icon failure).
	// May be nil when no additional detail is available.
	Detail map[string]string
}
