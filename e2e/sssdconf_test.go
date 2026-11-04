package e2e

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// settings returns the non-comment, non-blank lines of an sssd.conf.
func settings(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// TestTunedSSSDIsDefaultsPlusPushTimeouts keeps the e2e comparison honest:
// the tuned config is the default one plus settings appended to its last
// section ([domain/frict]).
func TestTunedSSSDIsDefaultsPlusPushTimeouts(t *testing.T) {
	defaults := settings(t, "sssd/sssd-defaults.conf")
	tuned := settings(t, "sssd/sssd.conf")
	if len(tuned) <= len(defaults) || !slices.Equal(tuned[:len(defaults)], defaults) {
		t.Fatalf("sssd.conf must be sssd-defaults.conf followed by extra settings\ndefaults: %q\ntuned:    %q", defaults, tuned)
	}
	for _, line := range tuned[len(defaults):] {
		if strings.HasPrefix(line, "[") {
			t.Fatalf("extra settings in sssd.conf must stay in the last section of sssd-defaults.conf, found %q", line)
		}
	}
}
