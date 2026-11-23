//go:build deploy

package deploy

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestWorkflowGate holds deploy.yml to what the approval gate relies on.
func TestWorkflowGate(t *testing.T) {
	src, err := os.ReadFile("../../.github/workflows/deploy.yml")
	if err != nil {
		t.Fatal(err)
	}
	head, jobs, _ := strings.Cut(string(src), "\njobs:\n")
	build, deploy, found := strings.Cut(jobs, "\n  deploy:\n")
	if !found {
		t.Fatal("deploy.yml has no deploy job after its build job")
	}

	_, on, _ := strings.Cut(head, "\non:\n")
	on, _, _ = strings.Cut(on, "\npermissions: {}\n")
	var triggers []string
	for _, m := range regexp.MustCompile(`(?m)^  (\w+):`).FindAllStringSubmatch(on, -1) {
		triggers = append(triggers, m[1])
	}
	if want := []string{"push", "workflow_dispatch"}; !slices.Equal(triggers, want) {
		t.Errorf("triggers = %q, want %q", triggers, want)
	}
	if !strings.Contains(on, "  push:\n    branches: [main]\n") {
		t.Error("push is not limited to main")
	}
	if strings.Count(jobs, "\n    runs-on: ") != 2 {
		t.Error("want exactly the build and deploy jobs")
	}
	if !strings.HasPrefix(build, "  build:\n    if: github.ref == 'refs/heads/main'\n") {
		t.Error("the build job is not limited to main")
	}
	if strings.Contains(head+build, "secrets") {
		t.Error("secrets outside the deploy job")
	}
	for _, want := range []string{
		"\n    environment: production\n",
		"    needs: build\n",
		"    concurrency:\n      group: production\n      cancel-in-progress: false\n",
		"          DIGEST: ${{ needs.build.outputs.digest }}\n",
	} {
		if strings.Count("\n"+deploy, want) != 1 {
			t.Errorf("the deploy job lacks %q", want)
		}
	}
	for _, m := range regexp.MustCompile(`uses: (\S+)`).FindAllStringSubmatch(jobs, -1) {
		if !regexp.MustCompile(`@[0-9a-f]{40}$`).MatchString(m[1]) {
			t.Errorf("%s is not pinned to a full SHA", m[1])
		}
	}
}
