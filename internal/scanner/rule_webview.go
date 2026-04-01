package scanner

import (
	"fmt"
	"strings"

	"github.com/nao1215/mobilepkg/internal/dex"
)

type insecureWebViewRule struct{}

func (r *insecureWebViewRule) Name() string { return "InsecureWebView" }

// webviewTarget defines a dangerous WebView API call to detect.
type webviewTarget struct {
	class     string
	method    string
	severity  string
	message   string
	checkTrue bool // if true, only flag when the boolean argument is true (const/4 v, 0x1)
}

// webviewTargets defines the dangerous WebView API calls to detect.
var webviewTargets = []webviewTarget{
	{
		class:     "android/webkit/WebSettings",
		method:    "setJavaScriptEnabled",
		severity:  "warn",
		message:   "WebView JavaScript enabled — may expose app to XSS if loading untrusted content",
		checkTrue: true,
	},
	{
		class:    "android/webkit/WebView",
		method:   "addJavascriptInterface",
		severity: "error",
		message:  "WebView JavaScript interface exposed — allows JavaScript to call native methods (critical on API < 17)",
	},
	{
		class:     "android/webkit/WebSettings",
		method:    "setAllowFileAccess",
		severity:  "warn",
		message:   "WebView file access enabled — may allow reading local files",
		checkTrue: true,
	},
	{
		class:     "android/webkit/WebSettings",
		method:    "setAllowUniversalAccessFromFileURLs",
		severity:  "error",
		message:   "WebView universal file access enabled — file:// URLs can access any origin",
		checkTrue: true,
	},
	// setMixedContentMode is handled separately in matchMixedContentMode
	// because it requires value-based analysis (only value 0 is dangerous).
	{
		class:     "android/webkit/WebView",
		method:    "setWebContentsDebuggingEnabled",
		severity:  "warn",
		message:   "WebView debugging enabled — allows inspecting WebView content via Chrome DevTools",
		checkTrue: true,
	},
}

// Android MIXED_CONTENT_* constants.
const (
	mixedContentAlwaysAllow      = 0
	mixedContentNeverAllow       = 1
	mixedContentCompatibilityOld = 2
)

func (r *insecureWebViewRule) Match(ctx *Context) []Finding {
	var findings []Finding
	seen := make(map[string]struct{})

	for i, df := range ctx.DexFiles {
		for _, wt := range webviewTargets {
			calls := df.FindMethodCalls(wt.class, wt.method)
			for _, cs := range calls {
				// If checkTrue is set, verify the argument is true (const/4 with value 1).
				// This check must run BEFORE dedup so that a safe (false) call
				// does not suppress a later dangerous (true) call in the same method.
				if wt.checkTrue && !isBoolArgTrue(df, cs) {
					continue
				}

				key := fmt.Sprintf("%s.%s@%s.%s", wt.class, wt.method, cs.CallerClass, cs.CallerMethod)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}

				severity, confidence, msg := adjustForLibrary(cs.CallerClass, wt.severity, wt.message)

				findings = append(findings, Finding{
					ID:          fmt.Sprintf("dex.webview.%s.%s", wt.method, sanitizeID(cs.CallerClass)),
					Category:    "dex_webview",
					Severity:    severity,
					Confidence:  confidence,
					Message:     msg,
					ArchivePath: ctx.dexName(i),
					Field:       fmt.Sprintf("%s->%s", cs.CallerClass, cs.CallerMethod),
					Matched:     fmt.Sprintf("%s.%s()", wt.class, wt.method),
					Offset:      int(cs.Offset),
				})
			}
		}

		// Detect WebView.loadUrl("http://...") — cleartext content loading.
		loadCalls := df.FindMethodCalls("android/webkit/WebView", "loadUrl")
		for _, cs := range loadCalls {
			key := fmt.Sprintf("loadUrl@%s.%s", cs.CallerClass, cs.CallerMethod)
			if _, ok := seen[key]; ok {
				continue
			}
			if url := getPrecedingConstString(df, cs); url != "" && strings.HasPrefix(strings.ToLower(url), "http://") {
				seen[key] = struct{}{}
				findings = append(findings, Finding{
					ID:          fmt.Sprintf("dex.webview.loadUrl_http.%s", sanitizeID(cs.CallerClass)),
					Category:    "dex_webview",
					Severity:    sevWarn,
					Confidence:  confHigh,
					Message:     fmt.Sprintf("WebView loads cleartext HTTP URL (in %s)", cs.CallerClass),
					ArchivePath: ctx.dexName(i),
					Field:       fmt.Sprintf("%s->%s", cs.CallerClass, cs.CallerMethod),
					Matched:     truncate(url, 80),
					Offset:      int(cs.Offset),
				})
			}
		}

		// Detect onReceivedSslError bypass (SslErrorHandler.proceed).
		sslCalls := df.FindMethodCalls("android/webkit/SslErrorHandler", "proceed")
		for _, cs := range sslCalls {
			key := fmt.Sprintf("sslBypass@%s.%s", cs.CallerClass, cs.CallerMethod)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			severity, confidence, msg := adjustForLibrary(cs.CallerClass, sevError, "SSL error bypassed — SslErrorHandler.proceed() called")

			findings = append(findings, Finding{
				ID:          fmt.Sprintf("dex.webview.ssl_bypass.%s", sanitizeID(cs.CallerClass)),
				Category:    "dex_webview",
				Severity:    severity,
				Confidence:  confidence,
				Message:     msg,
				ArchivePath: ctx.dexName(i),
				Field:       fmt.Sprintf("%s->%s", cs.CallerClass, cs.CallerMethod),
				Matched:     "SslErrorHandler.proceed()",
				Offset:      int(cs.Offset),
			})
		}

		// Detect setMixedContentMode with value-based analysis.
		mixedCalls := df.FindMethodCalls("android/webkit/WebSettings", "setMixedContentMode")
		for _, cs := range mixedCalls {
			key := fmt.Sprintf("setMixedContentMode@%s.%s", cs.CallerClass, cs.CallerMethod)
			if _, ok := seen[key]; ok {
				continue
			}

			val := getPrecedingIntArg(df, cs)
			var severity, message string
			switch val {
			case mixedContentAlwaysAllow:
				severity = sevWarn
				message = "WebView MIXED_CONTENT_ALWAYS_ALLOW (0) — allows loading HTTP resources in HTTPS pages"
			case mixedContentNeverAllow:
				continue // safe setting, skip
			case mixedContentCompatibilityOld:
				severity = sevInfo
				message = "WebView MIXED_CONTENT_COMPATIBILITY_MODE (2) — legacy mixed content behavior"
			default:
				// Unknown value or can't determine — report as info.
				severity = sevInfo
				message = "WebView mixed content mode explicitly configured — verify MIXED_CONTENT_ALWAYS_ALLOW (0) is not used"
			}
			seen[key] = struct{}{}

			severity, confidence, msg := adjustForLibrary(cs.CallerClass, severity, message)

			findings = append(findings, Finding{
				ID:          fmt.Sprintf("dex.webview.setMixedContentMode.%s", sanitizeID(cs.CallerClass)),
				Category:    "dex_webview",
				Severity:    severity,
				Confidence:  confidence,
				Message:     msg,
				ArchivePath: ctx.dexName(i),
				Field:       fmt.Sprintf("%s->%s", cs.CallerClass, cs.CallerMethod),
				Matched:     fmt.Sprintf("WebSettings.setMixedContentMode(%d)", val),
				Offset:      int(cs.Offset),
			})
		}
	}
	return findings
}

// getPrecedingIntArg looks backward from an invoke instruction for an
// integer constant loading instruction and returns the value. It checks
// const/4, const/16, and const (31i) instructions. Returns -1 if the
// value cannot be determined.
func getPrecedingIntArg(df *dex.File, cs dex.CallSite) int {
	data := df.RawData()
	if data == nil {
		return -1
	}
	off := int(cs.Offset)

	// const/4 (opcode 0x12): 2 bytes — [B|A] 12
	if off >= 2 {
		prevInsn := data[off-2 : off]
		if prevInsn[0] == 0x12 {
			val := int8(prevInsn[1]) >> 4
			return int(val)
		}
	}

	// const/16 (opcode 0x13): 4 bytes — [AA] 13 [BBBB]
	if off >= 4 {
		prevInsn := data[off-4 : off]
		if prevInsn[0] == 0x13 {
			val := int16(prevInsn[2]) | int16(prevInsn[3])<<8
			return int(val)
		}
	}

	// const (opcode 0x14): 6 bytes — [AA] 14 [BBBBBBBB]
	if off >= 6 {
		prevInsn := data[off-6 : off]
		if prevInsn[0] == 0x14 {
			val := int32(prevInsn[2]) | int32(prevInsn[3])<<8 | int32(prevInsn[4])<<16 | int32(prevInsn[5])<<24
			return int(val)
		}
	}

	return -1
}

// isBoolArgTrue performs lightweight argument tracking. It looks backward from
// the invoke-* instruction for a const/4 instruction with value 1 (true)
// in the same method. This is a heuristic: it checks whether the instruction
// immediately before the invoke is a const/4 with the literal 1.
func isBoolArgTrue(df *dex.File, cs dex.CallSite) bool {
	data := df.RawData()
	if data == nil {
		return true // conservative: if we can't check, assume true
	}

	off := int(cs.Offset)
	// Look at the 2 bytes immediately before the invoke instruction.
	// const/4 is opcode 0x12, encoded as: [B|A] 12 where B is the 4-bit value
	// and A is the destination register. Value 1 = true, 0 = false.
	if off >= 2 {
		prevInsn := data[off-2 : off]
		if prevInsn[0] == 0x12 {
			// The high nibble of byte 1 is the 4-bit signed value.
			val := int8(prevInsn[1]) >> 4
			return val == 1
		}
	}

	// Also check 4 bytes back for const/16 (opcode 0x13): [AA] 13 [BBBB]
	if off >= 4 {
		prevInsn := data[off-4 : off]
		if prevInsn[0] == 0x13 {
			val := int16(prevInsn[2]) | int16(prevInsn[3])<<8
			return val == 1
		}
	}

	// If we can't determine, be conservative and flag it.
	return true
}

// getPrecedingConstString looks for a const-string instruction immediately
// before the invoke and returns the loaded string if found.
func getPrecedingConstString(df *dex.File, cs dex.CallSite) string {
	data := df.RawData()
	if data == nil {
		return ""
	}
	off := int(cs.Offset)
	strs := df.Strings()

	// const-string (opcode 0x1A): 4 bytes — [AA] 1A [BBBB]
	if off >= 4 {
		prevOp := data[off-4]
		if prevOp == 0x1A {
			strIdx := int(data[off-2]) | int(data[off-1])<<8
			if strIdx < len(strs) {
				return strs[strIdx]
			}
		}
	}
	return ""
}
