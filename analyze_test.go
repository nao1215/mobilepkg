package mobilepkg_test

import (
	"testing"

	"github.com/nao1215/mobilepkg"
)

func TestNetworkEndpoint_Fields(t *testing.T) {
	t.Parallel()

	ep := mobilepkg.NetworkEndpoint{
		Scheme:     "https",
		Host:       "api.example.com",
		Port:       "443",
		Path:       "/v1/users",
		Source:     "info_plist",
		Confidence: mobilepkg.ConfidenceHigh,
	}

	if ep.Scheme != "https" {
		t.Errorf("Scheme = %q, want %q", ep.Scheme, "https")
	}
	if ep.Host != "api.example.com" {
		t.Errorf("Host = %q, want %q", ep.Host, "api.example.com")
	}
}

func TestSecretCandidate_Fields(t *testing.T) {
	t.Parallel()

	sc := mobilepkg.SecretCandidate{
		Kind:        "api_key",
		MaskedValue: "AKIA****",
		SHA256:      "abc123",
		Source:      "manifest",
		Confidence:  mobilepkg.ConfidenceHigh,
	}

	if sc.Kind != "api_key" {
		t.Errorf("Kind = %q, want %q", sc.Kind, "api_key")
	}
}

func TestExportedComponent_Fields(t *testing.T) {
	t.Parallel()

	ec := mobilepkg.ExportedComponent{
		Kind:       "service",
		Name:       "com.example.MyService",
		Exported:   true,
		Permission: "com.example.MY_PERM",
	}

	if ec.Kind != "service" {
		t.Errorf("Kind = %q, want %q", ec.Kind, "service")
	}
	if !ec.Exported {
		t.Error("Exported should be true")
	}
}
