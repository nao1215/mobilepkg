// Package cmdinfo provides build metadata for the mobilepkg CLI.
package cmdinfo

import "runtime/debug"

// Version is set at build time via ldflags:
//
//	-ldflags "-X github.com/nao1215/mobilepkg/internal/cmdinfo.Version=v1.0.0"
var Version string

// GetVersion returns the version string. It prefers the ldflags-injected
// value and falls back to the module version embedded by the Go toolchain.
func GetVersion() string {
	if Version != "" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return "dev"
}
