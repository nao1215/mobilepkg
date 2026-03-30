package scanner

import "fmt"

type insecureWebViewRule struct{}

func (r *insecureWebViewRule) Name() string { return "InsecureWebView" }

// webviewTargets defines the dangerous WebView API calls to detect.
var webviewTargets = []struct {
	class    string
	method   string
	severity string
	message  string
}{
	{
		class:    "android/webkit/WebSettings",
		method:   "setJavaScriptEnabled",
		severity: "warn",
		message:  "WebView JavaScript enabled — may expose app to XSS if loading untrusted content",
	},
	{
		class:    "android/webkit/WebView",
		method:   "addJavascriptInterface",
		severity: "error",
		message:  "WebView JavaScript interface exposed — allows JavaScript to call native methods (critical on API < 17)",
	},
	{
		class:    "android/webkit/WebSettings",
		method:   "setAllowFileAccess",
		severity: "warn",
		message:  "WebView file access enabled — may allow reading local files",
	},
	{
		class:    "android/webkit/WebSettings",
		method:   "setAllowUniversalAccessFromFileURLs",
		severity: "error",
		message:  "WebView universal file access enabled — file:// URLs can access any origin",
	},
}

func (r *insecureWebViewRule) Match(ctx *Context) []Finding {
	var findings []Finding
	seen := make(map[string]struct{})

	for i, df := range ctx.DexFiles {
		for _, wt := range webviewTargets {
			calls := df.FindMethodCalls(wt.class, wt.method)
			for _, cs := range calls {
				key := fmt.Sprintf("%s.%s@%s.%s", wt.class, wt.method, cs.CallerClass, cs.CallerMethod)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}

				findings = append(findings, Finding{
					ID:          fmt.Sprintf("dex.webview.%s.%s", wt.method, sanitizeID(cs.CallerClass)),
					Category:    "dex_webview",
					Severity:    wt.severity,
					Confidence:  "high",
					Message:     fmt.Sprintf("%s (in %s)", wt.message, cs.CallerClass),
					ArchivePath: ctx.dexName(i),
					Field:       fmt.Sprintf("%s->%s", cs.CallerClass, cs.CallerMethod),
					Matched:     fmt.Sprintf("%s.%s()", wt.class, wt.method),
					Offset:      int(cs.Offset),
				})
			}
		}
	}
	return findings
}
