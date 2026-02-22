package cmdinfo

import "testing"

func TestGetVersion(t *testing.T) {
	orig := Version
	defer func() { Version = orig }()

	Version = "v1.2.3"
	if got := GetVersion(); got != "v1.2.3" {
		t.Fatalf("GetVersion() = %q, want %q", got, "v1.2.3")
	}

	Version = ""
	if got := GetVersion(); got == "" {
		t.Fatal("GetVersion() returned empty string")
	}
}
