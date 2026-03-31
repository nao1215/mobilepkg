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
	{
		class:    "android/webkit/WebSettings",
		method:   "setMixedContentMode",
		severity: "info",
		message:  "WebView mixed content mode explicitly configured — verify MIXED_CONTENT_ALWAYS_ALLOW (0) is not used",
	},
	{
		class:     "android/webkit/WebView",
		method:    "setWebContentsDebuggingEnabled",
		severity:  "warn",
		message:   "WebView debugging enabled — allows inspecting WebView content via Chrome DevTools",
		checkTrue: true,
	},
}

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
			if url := getPrecedingConstString(df, cs); url != "" && strings.HasPrefix(url, "http://") {
				seen[key] = struct{}{}
				findings = append(findings, Finding{
					ID:          fmt.Sprintf("dex.webview.loadUrl_http.%s", sanitizeID(cs.CallerClass)),
					Category:    "dex_webview",
					Severity:    "warn",
					Confidence:  "high",
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
	}
	return findings
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
