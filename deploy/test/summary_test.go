//go:build deploy

package deploy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeGH answers `gh api PATH --jq FILTER` from runs.json, filtered by the
// real jq.
const fakeGH = `#!/bin/sh
echo "$2" > "$FAKE_GH_DIR/path"
exec jq -r "$4" "$FAKE_GH_DIR/runs.json"
`

func TestSummary(t *testing.T) {
	script, err := filepath.Abs("../../scripts/deploy-summary.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir, repo := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "gh"), []byte(fakeGH), 0o700); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) string {
		return must(t, "", nil, "git", append([]string{"-C", repo, "-c", "user.name=test", "-c", "user.email=test@example.com"}, args...)...)
	}
	git("init", "--quiet", "--initial-branch=main")
	commit := func(subject string) string {
		git("commit", "--quiet", "--allow-empty", "--message", subject)
		return git("rev-parse", "HEAD")
	}
	first := commit("first")
	second := commit("second")
	git("checkout", "--quiet", "-b", "side")
	side := commit("not on main")
	git("checkout", "--quiet", "main")
	commit("third ```` `x`")
	head := commit("fourth")
	digest := "sha256:" + strings.Repeat("a", 64)

	summary := func(t *testing.T, runs ...string) string {
		t.Helper()
		var list []string
		for i, sha := range runs {
			list = append(list, fmt.Sprintf(`{"run_number":%d,"head_sha":%q}`, i+1, sha))
		}
		if err := os.WriteFile(filepath.Join(dir, "runs.json"), []byte(`{"workflow_runs":[`+strings.Join(list, ",")+`]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(script, digest)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "FAKE_GH_DIR="+dir,
			"GITHUB_SERVER_URL=https://github.com", "GITHUB_REPOSITORY=frict-auth/frict-server", "GITHUB_SHA="+head)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		for _, want := range []string{"frict-server@" + digest, "/commit/" + head} {
			if !strings.Contains(string(out), want) {
				t.Errorf("summary lacks %q:\n%s", want, out)
			}
		}
		return string(out)
	}
	subjects := func(out string) string {
		_, list, _ := strings.Cut(out, "````\n")
		list, _, _ = strings.Cut(list, "\n````\n")
		var s []string
		for _, line := range strings.Split(list, "\n") {
			_, subject, _ := strings.Cut(line, " ")
			s = append(s, subject)
		}
		return strings.Join(s, "|")
	}

	for _, tc := range []struct {
		name     string
		runs     []string
		last     string
		subjects string
	}{
		{"newest run wins", []string{first, second}, second, "fourth|third ```` `x`"},
		{"a newer run of a commit not on main doesn't count", []string{second, side}, second, "fourth|third ```` `x`"},
		{"an unknown commit doesn't count", []string{first, strings.Repeat("0", 40)}, first, "fourth|third ```` `x`|second"},
		{"no deploy yet", nil, "", "fourth|third ```` `x`|second|first"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := summary(t, tc.runs...)
			if got := subjects(out); got != tc.subjects {
				t.Errorf("commits = %q, want %q", got, tc.subjects)
			}
			if tc.last == "" {
				if !strings.Contains(out, "none found") {
					t.Errorf("want none found:\n%s", out)
				}
			} else if want := "/compare/" + tc.last + "..." + head; !strings.Contains(out, want) {
				t.Errorf("summary lacks %q:\n%s", want, out)
			}
			path, err := os.ReadFile(filepath.Join(dir, "path"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(path), "workflows/deploy.yml/runs?branch=main&status=success") {
				t.Errorf("gh api %s", path)
			}
		})
	}
}
