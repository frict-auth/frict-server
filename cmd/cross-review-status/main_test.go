package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodSHA = "0123456789abcdef0123456789abcdef01234567"

func TestRunRejectsBeforeTouchingKeyOrNetwork(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	missingKey := []string{"--key-file", filepath.Join(dir, "absent.pem")}
	worldReadable := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(worldReadable, []byte("unused"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(worldReadable, 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		args    []string
		code    int
		wantErr string
	}{
		{"missing flags", []string{"--repo", "a/b"}, 2, "required"},
		{"bad repo", []string{"--repo", "frict-server", "--sha", goodSHA, "--state", "pending"}, 2, "owner/name"},
		{"short sha", []string{"--repo", "a/b", "--sha", "0123456", "--state", "pending"}, 2, "40-character"},
		{"bad state", []string{"--repo", "a/b", "--sha", goodSHA, "--state", "approved"}, 2, "not one of"},
		{"stray arg", []string{"--repo", "a/b", "--sha", goodSHA, "--state", "pending", "extra"}, 2, "unexpected"},
		{"world-readable key", []string{"--repo", "a/b", "--sha", goodSHA, "--state", "pending", "--key-file", worldReadable}, 1, "group or other"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append(append([]string{}, missingKey...), tc.args...)
			if code := run(args, &stdout, &stderr); code != tc.code {
				t.Errorf("exit = %d, want %d; stderr: %s", code, tc.code, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.wantErr) {
				t.Errorf("stderr %q does not mention %q", stderr.String(), tc.wantErr)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
		})
	}
}

func TestExpandHome(t *testing.T) {
	t.Setenv("HOME", "/home/tester")
	for in, want := range map[string]string{
		"~/.config/frict/k.pem": "/home/tester/.config/frict/k.pem",
		"/abs/k.pem":            "/abs/k.pem",
		"rel/k.pem":             "rel/k.pem",
		"~other/k.pem":          "~other/k.pem",
	} {
		got, err := expandHome(in)
		if err != nil || got != want {
			t.Errorf("expandHome(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}
