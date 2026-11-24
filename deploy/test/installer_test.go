//go:build deploy

package deploy

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInstallerCurrent holds deploy/install.sh and the hashes docs/deploy.md
// checks it with to what deploy/make-install.sh makes of deploy/.
func TestInstallerCurrent(t *testing.T) {
	tree := t.TempDir()
	for _, f := range []string{"deploy/make-install.sh", "deploy/setup.sh", "deploy/frict-deploy", "deploy/sudoers", "deploy/compose.yaml", "deploy/install.sh", "docs/deploy.md"} {
		src, err := os.ReadFile(filepath.Join("../..", f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(tree, filepath.Dir(f)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tree, f), src, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	must(t, "", nil, filepath.Join(tree, "deploy/make-install.sh"))
	for _, f := range []string{"deploy/install.sh", "docs/deploy.md"} {
		want, err := os.ReadFile(filepath.Join(tree, f))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join("../..", f))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("%s is out of date: run deploy/make-install.sh", f)
		}
	}
	src, blob := installer(t)
	sum := sha256.Sum256(src)
	doc := docBlock(t, "server, as a user with sudo, with `key` set to the line step 2 printed:")
	for _, want := range []string{"/git/blobs/" + blob + "\n", "\necho '" + hex.EncodeToString(sum[:]) + "  install.sh' | sha256sum --check --strict\n"} {
		if !strings.Contains(doc, want) {
			t.Errorf("docs/deploy.md's installer block lacks %q", want)
		}
	}
}
