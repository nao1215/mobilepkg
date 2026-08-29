package main

import "testing"

// TestHasTarget covers the distinction the runner cannot afford to get wrong:
// `--filter inspect` is a flag and its value, while `e2e/atago/inspect.atago.yaml`
// is a target. Read the first as a target and the runner stops appending the
// default spec directory, so `make e2e` would pass by running nothing at all.
func TestHasTarget(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		args []string
		want bool
	}{
		"no arguments at all":                      {nil, false},
		"a bare spec path is a target":             {[]string{"e2e/atago/inspect.atago.yaml"}, true},
		"a boolean flag alone is not a target":     {[]string{"--verbose"}, false},
		"a value flag consumes its next argument":  {[]string{"--filter", "inspect"}, false},
		"an inline value flag consumes nothing":    {[]string{"--filter=inspect"}, false},
		"a path after a value flag is a target":    {[]string{"--filter", "inspect", "e2e/atago"}, true},
		"a path after a boolean flag is a target":  {[]string{"--verbose", "e2e/atago"}, true},
		"parallel takes a value that is not a arg": {[]string{"--parallel", "4"}, false},
		"single-dash value flags behave the same":  {[]string{"-filter", "inspect"}, false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := hasTarget(tt.args); got != tt.want {
				t.Errorf("hasTarget(%q) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

// TestFirstLine keeps the version banner on one line no matter how many the
// binary prints.
func TestFirstLine(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in   string
		want string
	}{
		"a single line is returned as is":  {"mobilepkg v1.2.3", "mobilepkg v1.2.3"},
		"only the first of many is kept":   {"mobilepkg v1.2.3\nbuilt with go1.27", "mobilepkg v1.2.3"},
		"a trailing newline is trimmed":    {"mobilepkg v1.2.3\n", "mobilepkg v1.2.3"},
		"an empty string stays empty":      {"", ""},
		"a leading newline yields nothing": {"\nmobilepkg", ""},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := firstLine(tt.in); got != tt.want {
				t.Errorf("firstLine(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
