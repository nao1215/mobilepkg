package scanner

import (
	"fmt"
	"strings"
)

type dangerousAPIsRule struct{}

func (r *dangerousAPIsRule) Name() string { return "DangerousAPIs" }

// dangerousTarget defines a dangerous API call to detect.
type dangerousTarget struct {
	class    string
	method   string
	severity string
	message  string
}

var dangerousTargets = []dangerousTarget{
	{
		class:    "java/lang/Runtime",
		method:   "exec",
		severity: "error",
		message:  "Runtime.exec() called — potential command injection risk",
	},
	{
		class:    "java/lang/ProcessBuilder",
		method:   "<init>",
		severity: "warn",
		message:  "ProcessBuilder used — potential command execution",
	},
	{
		class:    "dalvik/system/DexClassLoader",
		method:   "<init>",
		severity: "error",
		message:  "DexClassLoader used — dynamic code loading may execute untrusted code",
	},
	{
		class:    "dalvik/system/PathClassLoader",
		method:   "<init>",
		severity: "warn",
		message:  "PathClassLoader used — dynamic code loading detected",
	},
	{
		class:    "java/lang/reflect/Method",
		method:   "invoke",
		severity: "info",
		message:  "reflection Method.invoke() used — may bypass access controls",
	},
	{
		class:    "android/telephony/SmsManager",
		method:   "sendTextMessage",
		severity: "warn",
		message:  "SmsManager.sendTextMessage() called — app can send SMS programmatically",
	},
	{
		class:    "android/telephony/SmsManager",
		method:   "sendMultipartTextMessage",
		severity: "warn",
		message:  "SmsManager.sendMultipartTextMessage() called — app can send SMS programmatically",
	},
	{
		class:    "android/app/admin/DevicePolicyManager",
		method:   "resetPassword",
		severity: "error",
		message:  "DevicePolicyManager.resetPassword() called — app can change device password",
	},
	{
		class:    "javax/crypto/Cipher",
		method:   "getInstance",
		severity: "info",
		message:  "cryptographic cipher usage detected — verify algorithm and mode are secure",
	},
}

func (r *dangerousAPIsRule) Match(ctx *Context) []Finding {
	var findings []Finding

	for _, dt := range dangerousTargets {
		if dt.severity == sevInfo {
			findings = append(findings, matchAggregated(ctx, dt)...)
		} else {
			findings = append(findings, matchPerCallsite(ctx, dt)...)
		}
	}
	return findings
}

// matchPerCallsite emits one finding per unique caller for error/warn APIs.
// This ensures new callers appear as new findings in baseline diff.
// When the caller belongs to a well-known library, severity is capped at
// "warn" and confidence is lowered to "medium" to reduce noise from
// expected library behavior (e.g. crash reporters calling Runtime.exec).
func matchPerCallsite(ctx *Context, dt dangerousTarget) []Finding {
	var findings []Finding
	seen := make(map[string]struct{})

	for i, df := range ctx.DexFiles {
		calls := df.FindMethodCalls(dt.class, dt.method)
		for _, cs := range calls {
			key := fmt.Sprintf("%s.%s", cs.CallerClass, cs.CallerMethod)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			severity := dt.severity
			confidence := confHigh
			msg := fmt.Sprintf("%s (in %s)", dt.message, cs.CallerClass)

			if isKnownLibraryClass(cs.CallerClass) {
				if severity == sevError {
					severity = sevWarn
				}
				confidence = confMedium
				msg = fmt.Sprintf("%s (in library %s)", dt.message, cs.CallerClass)
			}

			findings = append(findings, Finding{
				ID:          fmt.Sprintf("dex.api.%s.%s.%s", sanitizeID(dt.class), dt.method, sanitizeID(cs.CallerClass)),
				Category:    "dex_dangerous_api",
				Severity:    severity,
				Confidence:  confidence,
				Message:     msg,
				ArchivePath: ctx.dexName(i),
				Field:       fmt.Sprintf("%s->%s", cs.CallerClass, cs.CallerMethod),
				Matched:     fmt.Sprintf("%s.%s()", dt.class, dt.method),
				Offset:      int(cs.Offset),
			})
		}
	}
	return findings
}

// matchAggregated emits one finding per target API for info-severity APIs
// to avoid excessive noise from ubiquitous calls like Method.invoke.
func matchAggregated(ctx *Context, dt dangerousTarget) []Finding {
	var totalCalls int
	var firstCall *callInfo
	seen := make(map[string]struct{})

	for i, df := range ctx.DexFiles {
		calls := df.FindMethodCalls(dt.class, dt.method)
		for _, cs := range calls {
			key := fmt.Sprintf("%s.%s", cs.CallerClass, cs.CallerMethod)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			totalCalls++
			if firstCall == nil {
				firstCall = &callInfo{
					callerClass:  cs.CallerClass,
					callerMethod: cs.CallerMethod,
					offset:       int(cs.Offset),
					archivePath:  ctx.dexName(i),
				}
			}
		}
	}

	if totalCalls == 0 {
		return nil
	}

	msg := dt.message
	if totalCalls > 1 {
		msg = fmt.Sprintf("%s (%d call sites)", dt.message, totalCalls)
	}

	return []Finding{{
		ID:          fmt.Sprintf("dex.api.%s.%s", sanitizeID(dt.class), dt.method),
		Category:    "dex_dangerous_api",
		Severity:    dt.severity,
		Confidence:  confHigh,
		Message:     msg,
		ArchivePath: firstCall.archivePath,
		Field:       fmt.Sprintf("%s->%s", firstCall.callerClass, firstCall.callerMethod),
		Matched:     fmt.Sprintf("%s.%s()", dt.class, dt.method),
		Offset:      firstCall.offset,
	}}
}

type callInfo struct {
	callerClass  string
	callerMethod string
	offset       int
	archivePath  string
}

// knownLibraryPrefixes lists package prefixes for well-known third-party
// libraries and SDK code that are clearly not application-level code.
//
// Broad vendor prefixes (Lcom/google/, Lcom/facebook/, Lorg/chromium/)
// are intentionally excluded because they would also match first-party
// app code from those vendors, causing false severity downgrades.
// Only specific SDK sub-packages are listed.
var knownLibraryPrefixes = []string{
	// Android Jetpack / support libraries
	"Landroidx/",
	// Google SDKs (not first-party app code)
	"Lcom/google/firebase/",
	"Lcom/google/android/gms/",
	"Lcom/google/android/material/",
	"Lcom/google/android/play/",
	// Crash reporters
	"Lorg/acra/",
	"Lcom/crashlytics/",
	"Lio/sentry/",
	// Networking / serialization libraries
	"Lcom/squareup/",
	"Lokhttp3/",
	"Lretrofit2/",
	// Image loading
	"Lcom/bumptech/",
	// Reactive / coroutines
	"Lio/reactivex/",
	"Lkotlinx/",
	// Cloud SDKs
	"Lcom/amazonaws/",
	"Lcom/microsoft/",
}

// isKnownLibraryClass returns true if the caller class belongs to a
// well-known library or framework package.
func isKnownLibraryClass(callerClass string) bool {
	for _, prefix := range knownLibraryPrefixes {
		if strings.HasPrefix(callerClass, prefix) {
			return true
		}
	}
	return false
}
