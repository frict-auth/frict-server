//go:build deploy

// Package deploy runs deploy.yml's own build, push and deploy steps against a
// registry and a deployment server in containers: a real sshd with docs/deploy.md's forced
// command, a real Docker daemon, and frict-deploy as it runs in production.
package deploy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/frict-auth/frict-server/internal/store"
)

const (
	imageRepo = "frict-auth/frict-server"
	srvDir    = "/srv/frict"
	enrolled  = "user-enrolled-before-any-deploy"
)

// run executes a host command and returns its combined output and whether it
// succeeded.
func run(t *testing.T, stdin string, env []string, name string, args ...string) (string, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if _, exited := err.(*exec.ExitError); err != nil && !exited {
		t.Fatalf("%s %q: %v", name, args, err)
	}
	return string(out), err == nil
}

func must(t *testing.T, stdin string, env []string, name string, args ...string) string {
	t.Helper()
	out, ok := run(t, stdin, env, name, args...)
	if !ok {
		t.Fatalf("%s %q failed:\n%s", name, args, out)
	}
	return strings.TrimSpace(out)
}

// workflowStep returns the run script of the named step of deploy.yml.
func workflowStep(t *testing.T, name string) string {
	t.Helper()
	src, err := os.ReadFile("../../.github/workflows/deploy.yml")
	if err != nil {
		t.Fatal(err)
	}
	_, step, found := strings.Cut(string(src), "      - name: "+name+"\n")
	if !found {
		t.Fatalf("deploy.yml has no step %q", name)
	}
	_, script, found := strings.Cut(step, "        run: |\n")
	if !found {
		t.Fatalf("step %q has no run script", name)
	}
	var b strings.Builder
	for line := range strings.Lines(script) {
		body, inBlock := strings.CutPrefix(line, "          ")
		if !inBlock {
			break
		}
		b.WriteString(body)
	}
	return b.String()
}

type stack struct {
	env      []string // for docker compose
	registry string   // host:port of the registry as the host sees it
	key      string
	hosts    string // known_hosts line of the deployment server
	base     int    // app.frict.main-commit of the image the workflow built
	images   []string
	// installOut is what the first install printed; fresh is installed() after it.
	installOut, fresh string
}

func (s *stack) compose(t *testing.T, args ...string) string {
	t.Helper()
	return must(t, "", s.env, "docker", append([]string{"compose"}, args...)...)
}

// server runs a root shell script on the deployment server.
func (s *stack) server(t *testing.T, script string) string {
	t.Helper()
	return must(t, script, s.env, "docker", "compose", "exec", "-T", "server", "bash", "-euo", "pipefail", "-s")
}

// ssh runs the ssh client with the deploy key and arbitrary arguments.
func (s *stack) ssh(t *testing.T, args ...string) (string, bool) {
	t.Helper()
	return run(t, "", s.env, "docker", append([]string{"compose", "exec", "-T", "client",
		"ssh", "-F", "/dev/null", "-i", "/root/DEPLOY_SSH_KEY", "-o", "BatchMode=yes", "-o", "UserKnownHostsFile=/root/DEPLOY_KNOWN_HOSTS", "-o", "ConnectTimeout=10"}, args...)...)
}

// deployStep runs deploy.yml's deploy step.
func (s *stack) deployStep(t *testing.T, key, hosts, digest string) (string, bool) {
	t.Helper()
	return run(t, "", s.env, "docker", "compose", "exec", "-T",
		"-e", "DEPLOY_SSH_KEY="+key, "-e", "DEPLOY_KNOWN_HOSTS="+hosts, "-e", "DIGEST="+digest,
		"client", "bash", "-e", "-c", workflowStep(t, "Deploy this digest"))
}

func (s *stack) deploy(t *testing.T, digest string) (string, bool) {
	t.Helper()
	out, ok := s.deployStep(t, s.key, s.hosts, digest)
	t.Logf("deploy %s ok=%v\n%s", digest, ok, out)
	if strings.Contains(out, "level=INFO") || strings.Contains(out, "level=ERROR") {
		t.Errorf("frict-server's log reached the workflow's output")
	}
	return out, ok
}

func (s *stack) mustDeploy(t *testing.T, digest string) string {
	t.Helper()
	out, ok := s.deploy(t, digest)
	if !ok {
		t.Fatalf("deploy of %s failed", digest)
	}
	return out
}

// snapshot is everything a refused deploy must leave alone.
func (s *stack) snapshot(t *testing.T) string {
	t.Helper()
	return s.server(t, `cd `+srvDir+`
cat .env
find . -mindepth 1 -not -path './logs*' -not -name .lock -not -path './data/*' -printf '%p %u %m %T@\n' | sort
ls /tmp`) + "\n" + s.containers(t)
}

// containers identifies the deployment server's containers and when they started.
func (s *stack) containers(t *testing.T) string {
	t.Helper()
	return s.server(t, `docker ps --all --quiet | xargs docker inspect --format '{{.Id}} {{.Image}} {{.State.StartedAt}} {{.RestartCount}}'`)
}

// running returns the repository digest of the running container's image.
func (s *stack) running(t *testing.T) string {
	t.Helper()
	return s.server(t, `docker ps --quiet --filter label=com.docker.compose.project=frict | xargs -r docker inspect --format '{{.Image}}' | xargs -r docker image inspect --format '{{join .RepoDigests " "}}'`)
}

func (s *stack) healthz(t *testing.T) string {
	t.Helper()
	return s.server(t, `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8081/healthz || true`)
}

func (s *stack) wantServing(t *testing.T, digest string) {
	t.Helper()
	if got, want := s.running(t), "ghcr.io/"+imageRepo+"@"+digest; got != want {
		t.Errorf("running image = %q, want %q", got, want)
	}
	if got := s.healthz(t); got != "200" {
		t.Errorf("/healthz = %s, want 200", got)
	}
}

// push builds a Dockerfile in dir and returns its digest in the registry.
func (s *stack) push(t *testing.T, repo, dir, dockerfile string) string {
	t.Helper()
	ref := fmt.Sprintf("%s/%s:test%d", s.registry, repo, len(s.images))
	s.images = append(s.images, ref)
	must(t, dockerfile, nil, "docker", "build", "--quiet", "--provenance=false", "--tag", ref, "--file", "-", dir)
	out := must(t, "", nil, "docker", "push", ref)
	m := regexp.MustCompile(`sha256:[0-9a-f]{64}`).FindString(out[strings.LastIndex(out, "digest: "):])
	if m == "" {
		t.Fatalf("no digest in push output:\n%s", out)
	}
	return m
}

// variant pushes the workflow-built image as commit base+n on main, changed by
// extra Dockerfile lines.
func (s *stack) variant(t *testing.T, n int, dir, extra string) string {
	t.Helper()
	return s.push(t, imageRepo, dir, fmt.Sprintf("FROM %s/%s:built\nLABEL app.frict.main-commit=%d\n%s\n", s.registry, imageRepo, s.base+n, extra))
}

// patchedServer builds frict-server with source edits into a directory. Each
// edit is file, old, new.
func patchedServer(t *testing.T, edits ...[3]string) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	replace := map[string]string{}
	for i, e := range edits {
		src, err := os.ReadFile(filepath.Join(root, e[0]))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(src), e[1]) != 1 {
			t.Fatalf("%s: %q must occur once", e[0], e[1])
		}
		p := filepath.Join(dir, strconv.Itoa(i)+".go")
		if err := os.WriteFile(p, []byte(strings.Replace(string(src), e[1], e[2], 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		replace[filepath.Join(root, e[0])] = p
	}
	var pairs []string
	for k, v := range replace {
		pairs = append(pairs, fmt.Sprintf("%q:%q", k, v))
	}
	overlay := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlay, []byte(`{"Replace":{`+strings.Join(pairs, ",")+`}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	must(t, "", []string{"CGO_ENABLED=0"}, "go", "build", "-overlay", overlay, "-o", filepath.Join(dir, "frict-server"), "../../cmd/frict-server")
	return dir
}

const copyServer = "COPY frict-server /frict-server"

var (
	unhealthyEdit = [3]string{"internal/server/server.go", "\tif err := s.store.Ping(ctx); err != nil {", "\tif err := s.store.Ping(ctx); err == nil {"}
	migrationEdit = [3]string{"internal/store/store.go", "\tALTER TABLE users DROP COLUMN failed_attempts;`,", "\tALTER TABLE users DROP COLUMN failed_attempts;`,\n\t`CREATE TABLE newer (id INTEGER) STRICT;`,"}
)

// writeCerts makes a throwaway CA and a certificate for ghcr.io.
func writeCerts(t *testing.T, dir string) {
	t.Helper()
	write := func(name, typ string, der []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	check := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(err)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "throwaway CA"}, NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	check(err)
	write("ca.pem", "CERTIFICATE", caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(err)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "ghcr.io"}, NotAfter: time.Now().Add(24 * time.Hour), DNSNames: []string{"ghcr.io"}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	check(err)
	write("ghcr.pem", "CERTIFICATE", leafDER)
	keyDER, err := x509.MarshalECPrivateKey(key)
	check(err)
	write("ghcr.key", "EC PRIVATE KEY", keyDER)
}

// ghShim stands in for gh on the workstation: `gh secret set NAME` keeps the
// secret in /root/NAME.
const ghShim = `#!/bin/sh
if [ "$1 $2" != "secret set" ] || [ "$4 $5 $6 $7" != "--repo frict-auth/frict-server --env production" ] || [ $# != 7 ]; then
  echo "unexpected: gh $*" >&2; exit 1
fi
umask 077
cat > "/root/$3"
`

// curlShim stands in for curl on the deployment server for docs/deploy.md's
// download: it serves /opt/fetch/blobs/ID for GitHub's URL of blob ID.
const curlShim = `#!/bin/bash
if [[ $# != 5 || $1 != -fsSLo || $3 != -H || $4 != 'Accept: application/vnd.github.raw+json' ||
  ! $5 =~ ^https://api\.github\.com/repos/frict-auth/frict-server/git/blobs/([0-9a-f]{40})$ ]]; then
  echo "unexpected: curl $*" >&2; exit 2
fi
cp "/opt/fetch/blobs/${BASH_REMATCH[1]}" "$2" || exit 22
`

// gitBlob returns the git blob id of a file's content.
func gitBlob(content []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", len(content))
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

// installer returns deploy/install.sh and its git blob id.
func installer(t *testing.T) ([]byte, string) {
	t.Helper()
	src, err := os.ReadFile("../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	return src, gitBlob(src)
}

// serve makes the curl stand-in answer the installer's blob id with content.
func (s *stack) serve(t *testing.T, content []byte) {
	t.Helper()
	_, blob := installer(t)
	must(t, string(content), s.env, "docker", "compose", "exec", "-T", "server", "sh", "-c", "mkdir -p /opt/fetch/blobs && cat > /opt/fetch/blobs/"+blob)
}

// install runs docs/deploy.md's installer block on the deployment server with
// key, through the curl stand-in.
func (s *stack) install(t *testing.T, key string) (string, bool) {
	t.Helper()
	block := docBlock(t, "server, as a user with sudo, with `key` set to the line step 2 printed:")
	if strings.Count(block, "key='<public key line>'\n") != 1 {
		t.Fatal("docs/deploy.md's installer block has no key='<public key line>' line")
	}
	block = strings.Replace(block, "key='<public key line>'", "key='"+key+"'", 1)
	return run(t, block, s.env, "docker", "compose", "exec", "-T", "-e", "PATH=/opt/fetch:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"server", "bash", "-s")
}

func (s *stack) mustInstall(t *testing.T, key string) string {
	t.Helper()
	out, ok := s.install(t, key)
	t.Logf("install ok=%v\n%s", ok, out)
	if !ok {
		t.Fatal("docs/deploy.md's installer block failed")
	}
	return out
}

// workstation runs a shell script on the workstation.
func (s *stack) workstation(t *testing.T, script string) string {
	t.Helper()
	return must(t, script, s.env, "docker", "compose", "exec", "-T", "client", "bash", "-s")
}

// installed is what the installer owns on the deployment server: the user,
// its rights, and owner, mode and, for the files it replaces, content of each
// path it makes.
func (s *stack) installed(t *testing.T) string {
	t.Helper()
	return s.server(t, `getent passwd frict-deploy | cut -d: -f1,6,7
id -nG frict-deploy
sudo -l -U frict-deploy | sed '1,/may run the following commands/d'
for f in /usr/local/bin/frict-deploy /etc/sudoers.d/frict-deploy /srv/frict/compose.yaml; do
  printf '%s %s %s\n' "$f" "$(stat -c '%U:%G %a' "$f")" "$(sha256sum < "$f" | cut -d' ' -f1)"
done
for f in /home/frict-deploy/.ssh /home/frict-deploy/.ssh/authorized_keys /srv/frict /srv/frict/frict.env /srv/frict/data /srv/frict/secrets /srv/frict/secrets/duo-client-secret; do
  printf '%s %s\n' "$f" "$(stat -c '%U:%G %a' "$f")"
done`)
}

// kept is what the installer must keep when it runs again.
func (s *stack) kept(t *testing.T) string {
	t.Helper()
	return s.server(t, `cd /srv/frict
sha256sum frict.env secrets/* /home/frict-deploy/.ssh/authorized_keys`)
}

// up starts the stack and sets the deployment server up as docs/deploy.md does.
func up(t *testing.T) *stack {
	t.Helper()
	certs := t.TempDir()
	if err := os.Chmod(certs, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCerts(t, certs)
	s := &stack{env: []string{"CERTS=" + certs, "COMPOSE_PROGRESS=quiet"}}
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := run(t, "", s.env, "docker", "compose", "exec", "-T", "server", "sh", "-c", "tail -n 100 "+srvDir+"/logs/*")
			t.Logf("server logs:\n%s", out)
		}
		s.compose(t, "down", "--volumes", "--remove-orphans")
		if len(s.images) > 0 {
			must(t, "", nil, "docker", append([]string{"image", "rm", "--no-prune"}, s.images...)...)
		}
	})
	s.compose(t, "down", "--volumes", "--remove-orphans")
	s.compose(t, "up", "--build", "--detach")
	s.registry = s.compose(t, "port", "registry", "443")
	must(t, ghShim, s.env, "docker", "compose", "exec", "-T", "client", "install", "-m", "0755", "/dev/stdin", "/usr/local/bin/gh")
	must(t, curlShim, s.env, "docker", "compose", "exec", "-T", "server", "sh", "-c", "mkdir -p /opt/fetch && install -m 0755 /dev/stdin /opt/fetch/curl")
	src, _ := installer(t)
	s.serve(t, src)

	out := s.workstation(t, docBlock(t, "On your workstation, make the deploy key:"))
	pub := regexp.MustCompile(`(?m)^ssh-ed25519 \S+ frict-deploy$`).FindString(out)
	if pub == "" || strings.Contains(out, "PRIVATE KEY") {
		t.Fatalf("the deploy key block printed %q, want the public key line and no private key", out)
	}
	if left := s.workstation(t, `grep -rlF 'PRIVATE KEY' /root /tmp || true`); left != "/root/DEPLOY_SSH_KEY" {
		t.Errorf("private key files on the workstation: %q, want only the DEPLOY_SSH_KEY secret", left)
	}

	s.server(t, `for i in $(seq 60); do docker version >/dev/null 2>&1 && break; sleep 0.5; done; docker version >/dev/null`)
	s.installOut = s.mustInstall(t, pub)
	hostsCmd := regexp.MustCompile(`(?m)^printf .* \| gh secret set DEPLOY_KNOWN_HOSTS .*$`).FindString(s.installOut)
	if hostsCmd == "" {
		t.Fatalf("the installer printed no gh secret set DEPLOY_KNOWN_HOSTS command:\n%s", s.installOut)
	}
	s.workstation(t, hostsCmd)
	s.key = s.workstation(t, "cat /root/DEPLOY_SSH_KEY")
	s.hosts = s.workstation(t, "cat /root/DEPLOY_KNOWN_HOSTS")
	s.fresh = s.installed(t)

	s.server(t, `base64 -d > `+srvDir+`/data/frict.db <<'DB'
`+database(t)+`
DB
chown 65532:65532 `+srvDir+`/data/frict.db`)
	return s
}

// database returns a base64 SQLite database with one user.
func database(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "frict.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateEnrollment(context.Background(), "DU1", enrolled, "code", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(db)
}

// build runs deploy.yml's build and push steps, which publish to the
// stack's registry, and returns the digest they output.
func (s *stack) build(t *testing.T) string {
	t.Helper()
	output := filepath.Join(t.TempDir(), "output")
	sha := must(t, "", nil, "git", "rev-parse", "HEAD")
	env := []string{"IMAGE=" + s.registry + "/" + imageRepo, "GITHUB_SHA=" + sha, "GITHUB_SERVER_URL=https://github.com", "GITHUB_REPOSITORY=" + imageRepo,
		"GITHUB_ACTOR=test", "REGISTRY_TOKEN=test", "GITHUB_OUTPUT=" + output, "DOCKER_CONFIG=" + t.TempDir()}
	for _, step := range []string{"Build", "Push"} {
		cmd := exec.Command("bash", "-e", "-c", workflowStep(t, step))
		cmd.Dir = "../.."
		cmd.Env = append(os.Environ(), env...)
		out, err := cmd.CombinedOutput()
		t.Logf("step %s:\n%s", step, out)
		if err != nil {
			t.Fatalf("step %s: %v", step, err)
		}
	}
	out, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	digest, found := strings.CutPrefix(strings.TrimSpace(string(out)), "digest=")
	if !found {
		t.Fatalf("GITHUB_OUTPUT = %q", out)
	}
	ref := env[0][len("IMAGE="):] + ":" + sha
	built := s.registry + "/" + imageRepo + ":built"
	must(t, "", nil, "docker", "tag", ref, built)
	s.images = append(s.images, ref, built)
	s.base, err = strconv.Atoi(must(t, "", nil, "docker", "image", "inspect", "--format", `{{index .Config.Labels "app.frict.main-commit"}}`, ref))
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestDeploy(t *testing.T) {
	s := up(t)
	v0 := s.build(t)
	unhealthyDir := patchedServer(t, unhealthyEdit)
	crash := s.variant(t, 1, unhealthyDir, "ENV FRICT_CHALLENGE_TTL=crash")
	v1 := s.variant(t, 2, unhealthyDir, "")
	unhealthy := s.variant(t, 3, unhealthyDir, copyServer)
	v4 := s.variant(t, 4, unhealthyDir, "")
	migrates := s.variant(t, 5, patchedServer(t, unhealthyEdit, migrationEdit), copyServer)
	unlabelled := s.push(t, imageRepo, unhealthyDir, "FROM scratch\n"+copyServer+"\nUSER 65532:65532\nENTRYPOINT [\"/frict-server\"]\n")
	hostileLabel := s.push(t, imageRepo, unhealthyDir, "FROM scratch\n"+copyServer+"\nLABEL app.frict.main-commit='x[$(touch /tmp/pwned)]'\n")
	other := s.push(t, "frict-auth/other", unhealthyDir, "FROM scratch\n"+copyServer+"\n")

	t.Run("the deploy user can't use docker, nor sudo but for the script", func(t *testing.T) {
		check := s.server(t, docBlock(t, "Check the user's groups and sudo rights:"))
		if want := "frict-deploy\n    (root) NOPASSWD: /usr/local/bin/frict-deploy \"\""; check != want {
			t.Errorf("docs/deploy.md's check printed\n%s\nwant\n%s", check, want)
		}
		for _, c := range []struct{ cmd, refusal string }{
			{"docker version", "permission denied"},
			{"sudo -n true", "sudo: a password is required"},
			{"sudo -n docker version", "sudo: a password is required"},
			{"sudo -n /usr/local/bin/frict-deploy " + v1, "sudo: a password is required"},
		} {
			out, ok := run(t, "", s.env, "docker", "compose", "exec", "-T", "server", "runuser", "-u", "frict-deploy", "--", "sh", "-c", c.cmd)
			if ok || !strings.Contains(out, c.refusal) {
				t.Errorf("%s as frict-deploy: ok=%v, want %q: %s", c.cmd, ok, c.refusal, out)
			}
		}
	})

	t.Run("the installer makes the Duo credentials and prints what Authentik needs", func(t *testing.T) {
		env := s.server(t, "cat "+srvDir+"/frict.env")
		m := regexp.MustCompile(`^FRICT_API_HOSTNAME=api\.frict\.app\nFRICT_CLIENT_ID=(DI[0-9A-F]{18})$`).FindStringSubmatch(env)
		if m == nil {
			t.Fatalf("frict.env = %q, want the API hostname and a generated client ID", env)
		}
		secret := s.server(t, "cat "+srvDir+"/secrets/duo-client-secret")
		if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(secret) {
			t.Errorf("duo-client-secret = %q, want 40 random hex digits", secret)
		}
		for _, want := range []string{"API hostname api.frict.app, client ID " + m[1] + ",", "client secret: sudo cat " + srvDir + "/secrets/duo-client-secret"} {
			if !strings.Contains(s.installOut, want) {
				t.Errorf("the installer's output lacks %q", want)
			}
		}
		if strings.Contains(s.installOut, secret) {
			t.Error("the installer printed the client secret")
		}
	})

	t.Run("running the installer again keeps the key, configuration and secrets", func(t *testing.T) {
		kept := s.kept(t)
		out := s.mustInstall(t, "")
		if got := s.installed(t); got != s.fresh {
			t.Errorf("installed:\n%s\nwant as after the first install:\n%s", got, s.fresh)
		}
		if got := s.kept(t); got != kept {
			t.Errorf("changed:\n--- before\n%s\n--- after\n%s", kept, got)
		}
		if strings.Contains(out, "No deploy key") {
			t.Errorf("the installer says there is no deploy key:\n%s", out)
		}
	})

	t.Run("first deploy that fails leaves nothing running and says so", func(t *testing.T) {
		out, ok := s.deploy(t, crash)
		if ok || !strings.Contains(out, "SERVER IS DOWN: there is no previous version") {
			t.Errorf("ok=%v, want a failure that says the server is down", ok)
		}
		if got := s.running(t); got != "" {
			t.Errorf("running %q, want nothing", got)
		}
	})

	t.Run("build is deployable and runs as 65532 on loopback only", func(t *testing.T) {
		// The failed first deploy recorded nothing, so the older build is accepted.
		s.mustDeploy(t, v0)
		s.wantServing(t, v0)
		uid := s.server(t, `awk '/^Uid:/ {print $2, $3}' /proc/$(docker inspect --format '{{.State.Pid}}' frict-frict-server-1)/status`)
		if uid != "65532 65532" {
			t.Errorf("server process uids = %q, want 65532", uid)
		}
		got := s.server(t, `docker inspect --format '{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}}' frict-frict-server-1`)
		if want := "true [ALL] [no-new-privileges:true]"; got != want {
			t.Errorf("hardening = %s, want %s", got, want)
		}
		listeners := s.server(t, `docker port frict-frict-server-1`)
		if want := "8080/tcp -> 127.0.0.1:8081"; listeners != want {
			t.Errorf("published ports = %q, want %q", listeners, want)
		}
		if out, ok := run(t, "", s.env, "docker", "compose", "exec", "-T", "client", "curl", "-sS", "--max-time", "5", "http://api.frict.app:8081/healthz"); ok || !strings.Contains(out, "curl: (7)") {
			t.Errorf("from another host: ok=%v %q, want no connection", ok, out)
		}
		roots := s.server(t, `docker cp frict-frict-server-1:/etc/ssl/certs/ca-certificates.crt - | tar -xO`)
		if !x509.NewCertPool().AppendCertsFromPEM([]byte(roots)) {
			t.Errorf("the image has no CA certificates to reach FCM with")
		}
	})

	t.Run("a proxy on the deployment server is the pinned gateway, so its X-Forwarded-For names the client", func(t *testing.T) {
		ipam := s.server(t, `docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}} {{.Gateway}}{{end}}' frict_default`)
		if want := "10.231.0.0/24 10.231.0.1"; ipam != want {
			t.Errorf("frict_default subnet and gateway = %q, want %q", ipam, want)
		}
		for _, c := range []struct{ header, clientIP string }{
			{"X-Probe: none", "10.231.0.1"},
			{"X-Forwarded-For: 203.0.113.7", "203.0.113.7"},
		} {
			log := s.server(t, `since=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
curl -sS -o /dev/null -X POST -H '`+c.header+`' http://127.0.0.1:8081/device/v1/pending
docker logs --since "$since" frict-frict-server-1 2>&1 | grep -F event=device_signature_rejected`)
			if !strings.HasSuffix(log, " client_ip="+c.clientIP) || strings.Count(log, "\n") != 0 {
				t.Errorf("request with %q logged %q, want client_ip=%s", c.header, log, c.clientIP)
			}
		}
	})

	t.Run("a download that doesn't match docs/deploy.md runs nothing", func(t *testing.T) {
		src, _ := installer(t)
		before := s.snapshot(t) + s.installed(t) + s.kept(t)
		s.serve(t, []byte(strings.Replace(string(src), "\n", "\ntouch /tmp/pwned\n", 1)))
		out, ok := s.install(t, "")
		s.serve(t, src)
		if ok || !strings.Contains(out, "install.sh: FAILED") {
			t.Errorf("ok=%v, want sha256sum to fail:\n%s", ok, out)
		}
		if after := s.snapshot(t) + s.installed(t) + s.kept(t); before != after {
			t.Errorf("changed:\n--- before\n%s\n--- after\n%s", before, after)
		}
	})

	t.Run("the installer refuses anything but one ed25519 key line", func(t *testing.T) {
		before := s.snapshot(t) + s.installed(t) + s.kept(t)
		pub := s.workstation(t, "ssh-keygen -y -f /root/DEPLOY_SSH_KEY | cut -d' ' -f1,2")
		other := s.workstation(t, "ssh-keygen -q -t ed25519 -N '' -f /root/other && cut -d' ' -f1,2 /root/other.pub")
		rsa := s.workstation(t, "ssh-keygen -q -t rsa -N '' -f /root/rsa && cat /root/rsa.pub")
		for _, key := range []string{
			pub + "\n" + other,
			pub + "\n",
			`command="/bin/sh" ` + pub,
			pub[:len(pub)-1],
			pub + "A",
			rsa,
		} {
			out, ok := s.install(t, key)
			if ok || !strings.Contains(out, "want at most one argument, one ssh-ed25519 public key line. Nothing changed.") {
				t.Errorf("key %q: ok=%v, want a refusal:\n%s", key, ok, out)
			}
		}
		if after := s.snapshot(t) + s.installed(t) + s.kept(t); before != after {
			t.Errorf("changed:\n--- before\n%s\n--- after\n%s", before, after)
		}
	})

	t.Run("refused input changes nothing", func(t *testing.T) {
		before := s.snapshot(t)
		hex := strings.TrimPrefix(v1, "sha256:")
		refuse := func(sshArgs []string, name, refusal string) {
			t.Helper()
			out, ok := s.ssh(t, sshArgs...)
			t.Logf("%q ok=%v %s", name, ok, out)
			if ok || !strings.Contains(out, refusal) {
				t.Errorf("%q: ok=%v, want %s: %s", name, ok, refusal, out)
			}
		}
		for _, cmd := range []string{
			"",
			" ",
			"latest",
			"sha256:",
			"sha256:" + hex[1:],
			"sha256:" + hex + "0",
			"sha256:" + strings.ToUpper(hex),
			"sha512:" + hex,
			hex,
			v1 + " ",
			" " + v1,
			v1 + "\n",
			v1 + "\n" + v1,
			v1 + " " + v1,
			v1 + "; touch /tmp/pwned",
			v1 + " && touch /tmp/pwned",
			v1 + " | touch /tmp/pwned",
			v1 + "\ntouch /tmp/pwned",
			"$(touch /tmp/pwned)",
			"`touch /tmp/pwned`",
			"touch /tmp/pwned",
			"bash -c 'touch /tmp/pwned'",
			"sha256:$(touch /tmp/pwned)" + hex[:40],
			"sha256:*",
			"ghcr.io/" + imageRepo + ":latest",
			"ghcr.io/" + imageRepo + "@" + v1,
			"ghcr.io/frict-auth/other@" + other,
			"docker ps",
			"sudo -n true",
			"sudo -n -i",
			"/usr/bin/sudo -n /usr/local/bin/frict-deploy " + v1,
			"internal-sftp",
		} {
			args := []string{"frict-deploy@api.frict.app"}
			if cmd != "" {
				args = append(args, cmd)
			}
			refuse(args, cmd, "REFUSED: want sha256:")
		}
		for _, digest := range []struct{ name, digest, refusal string }{
			{"unknown digest", "sha256:" + strings.Repeat("0", 64), "REFUSED: cannot pull"},
			{"another image's digest", other, "REFUSED: cannot pull"},
			{"an image the workflow didn't build", unlabelled, "REFUSED: the image has no app.frict.main-commit label"},
			{"a command in the label", hostileLabel, "REFUSED: the image has no app.frict.main-commit label"},
		} {
			refuse([]string{"frict-deploy@api.frict.app", digest.digest}, digest.name, digest.refusal)
		}
		if out, ok := s.ssh(t, "-s", "frict-deploy@api.frict.app", "sftp"); ok {
			t.Errorf("sftp: ok=%v, want a failure: %s", ok, out)
		}
		if out, ok := s.ssh(t, "-tt", "frict-deploy@api.frict.app", "sh"); ok || !strings.Contains(out, "PTY allocation request failed") {
			t.Errorf("pty: ok=%v, want no pty: %s", ok, out)
		}
		if out, ok := s.ssh(t, "-W", "127.0.0.1:8081", "frict-deploy@api.frict.app"); ok || !strings.Contains(out, "administratively prohibited") {
			t.Errorf("forwarding: ok=%v, want prohibited: %s", ok, out)
		}
		if after := s.snapshot(t); before != after {
			t.Errorf("changed:\n--- before\n%s\n--- after\n%s", before, after)
		}
	})

	t.Run("workflow step fails before connecting without a secret and on a wrong host key", func(t *testing.T) {
		before := s.snapshot(t)
		for name, args := range map[string][3]string{
			"DEPLOY_SSH_KEY":     {"", s.hosts, v1},
			"DEPLOY_KNOWN_HOSTS": {s.key, "", v1},
			"DIGEST":             {s.key, s.hosts, ""},
		} {
			out, ok := s.deployStep(t, args[0], args[1], args[2])
			if want := "::error::" + name + " is empty"; ok || !strings.HasPrefix(out, want) {
				t.Errorf("ok=%v %q, want %q", ok, out, want)
			}
		}
		wrong := s.compose(t, "exec", "-T", "client", "sh", "-c", "ssh-keygen -q -t ed25519 -N '' -f /root/wrong && printf 'api.frict.app ' && cut -d' ' -f1,2 /root/wrong.pub")
		if out, ok := s.deployStep(t, s.key, wrong, v1); ok || !strings.Contains(out, "Host key verification failed") {
			t.Errorf("wrong host key: ok=%v %s", ok, out)
		}
		if out, ok := s.deployStep(t, s.key, "other.example "+strings.TrimPrefix(s.hosts, "api.frict.app "), v1); ok || !strings.Contains(out, "Host key verification failed") {
			t.Errorf("unknown host: ok=%v %s", ok, out)
		}
		if after := s.snapshot(t); before != after {
			t.Errorf("changed:\n--- before\n%s\n--- after\n%s", before, after)
		}
	})

	t.Run("newer build replaces the running one, with a backup", func(t *testing.T) {
		s.mustDeploy(t, v1)
		s.wantServing(t, v1)
		env := s.server(t, "cat "+srvDir+"/.env")
		if want := fmt.Sprintf("FRICT_DIGEST=%s\nFRICT_MAIN_COMMIT=%d\nFRICT_PREVIOUS_DIGEST=%s", v1, s.base+2, v0); env != want {
			t.Errorf(".env = %q, want %q", env, want)
		}
		tar := s.server(t, `cd `+srvDir+`/backups; tar --numeric-owner -tvf "$(ls -t | head -1)"`)
		if !regexp.MustCompile(`(?m)^-\S+ 65532/65532 +[1-9]\d* .* data/frict\.db$`).MatchString(tar) {
			t.Errorf("newest backup has no database owned by 65532:\n%s", tar)
		}
	})

	t.Run("redeploying the running digest restarts nothing", func(t *testing.T) {
		before := s.containers(t)
		env := s.server(t, "cat "+srvDir+"/.env")
		s.mustDeploy(t, v1)
		if got := s.server(t, "cat "+srvDir+"/.env"); got != env {
			t.Errorf(".env = %q, want %q", got, env)
		}
		if after := s.containers(t); before != after {
			t.Errorf("containers changed:\n--- before\n%s\n--- after\n%s", before, after)
		}
	})

	t.Run("redeploying the digest of a stopped server starts it", func(t *testing.T) {
		s.server(t, "docker stop frict-frict-server-1")
		s.mustDeploy(t, v1)
		s.wantServing(t, v1)
	})

	t.Run("older build is refused", func(t *testing.T) {
		before := s.snapshot(t)
		out, ok := s.deploy(t, v0)
		if ok || !strings.Contains(out, "older than the deployed") {
			t.Errorf("ok=%v, want a refusal", ok)
		}
		if after := s.snapshot(t); before != after {
			t.Errorf("changed:\n--- before\n%s\n--- after\n%s", before, after)
		}
	})

	t.Run("broken compose file is refused while the server keeps running", func(t *testing.T) {
		s.server(t, "mv "+srvDir+"/frict.env "+srvDir+"/frict.env.away")
		out, ok := s.deploy(t, v4)
		s.server(t, "mv "+srvDir+"/frict.env.away "+srvDir+"/frict.env")
		if ok || !strings.Contains(out, "REFUSED") {
			t.Errorf("ok=%v, want a refusal", ok)
		}
		s.wantServing(t, v1)
	})

	t.Run("a healthy container of another digest fails the deploy", func(t *testing.T) {
		s.server(t, "sed -i 's/@\\${FRICT_DIGEST.*/@"+v1+"/' "+srvDir+"/compose.yaml")
		out, ok := s.deploy(t, v4)
		s.server(t, "install -o root -g root -m 0644 /src/deploy/compose.yaml "+srvDir+"/compose.yaml")
		if ok || !strings.Contains(out, "the running container is not ghcr.io/"+imageRepo+"@"+v4) {
			t.Errorf("ok=%v, want a failure that says which image isn't running", ok)
		}
		s.wantServing(t, v1)
	})

	t.Run("unhealthy build goes back and fails", func(t *testing.T) {
		env := s.server(t, "cat "+srvDir+"/.env")
		out, ok := s.deploy(t, unhealthy)
		if ok || !strings.Contains(out, "/healthz did not answer 200") || !strings.Contains(out, "WENT BACK: ghcr.io/"+imageRepo+"@"+v1) {
			t.Errorf("ok=%v, want a failure that says it went back to %s", ok, v1)
		}
		s.wantServing(t, v1)
		if got := s.server(t, "cat "+srvDir+"/.env"); got != env {
			t.Errorf(".env = %q, want %q", got, env)
		}
		if log := s.server(t, "cat "+srvDir+"/logs/*-server-"+unhealthy[7:19]+".log"); !strings.Contains(log, "store unavailable") {
			t.Errorf("the failed server's log wasn't kept: %q", log)
		}
	})

	t.Run("deploy outlives its SSH connection and refuses a second one", func(t *testing.T) {
		// docker pull waits on the paused registry, so the deploy is under way
		// when its client dies.
		s.compose(t, "pause", "registry")
		ctx, cancel := context.WithCancel(context.Background())
		var out bytes.Buffer
		cmd := exec.CommandContext(ctx, "docker", "compose", "exec", "-T", "-e", "LANG=from-client", "-e", "LC_PROBE=from-client", "client",
			"ssh", "-F", "/dev/null", "-i", "/root/DEPLOY_SSH_KEY", "-o", "UserKnownHostsFile=/root/DEPLOY_KNOWN_HOSTS", "-o", "SendEnv=LANG LC_PROBE",
			"frict-deploy@api.frict.app", v4)
		cmd.Env, cmd.Stdout, cmd.Stderr = append(os.Environ(), s.env...), &out, &out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		s.server(t, `for i in $(seq 100); do pgrep -f 'docker pull' >/dev/null && exit 0; sleep 0.1; done; exit 1`)
		env := s.server(t, `tr '\0' '\n' </proc/$(pgrep -o -x frict-deploy)/environ | sort`)
		names := regexp.MustCompile(`(?m)=.*$`).ReplaceAllString(env, "")
		if want := "HOME LANG LOGNAME MAIL PATH SHELL SSH_ORIGINAL_COMMAND SUDO_COMMAND SUDO_GID SUDO_UID SUDO_USER TERM USER"; strings.Join(strings.Fields(names), " ") != want ||
			!strings.Contains(env, "\nSSH_ORIGINAL_COMMAND="+v4+"\n") || strings.Contains(env, "from-client") {
			t.Errorf("frict-deploy's environment:\n%s\nwant the names %s, SSH_ORIGINAL_COMMAND=%s and nothing from the client", env, want, v4)
		}
		if out, ok := s.ssh(t, "frict-deploy@api.frict.app", v4); ok || !strings.Contains(out, "another deploy is running") {
			t.Errorf("second deploy: ok=%v %s", ok, out)
		}
		s.compose(t, "exec", "-T", "client", "pkill", "-9", "-x", "ssh")
		cancel()
		cmd.Wait()
		s.server(t, `for i in $(seq 100); do pgrep -f 'sshd: frict-deploy' >/dev/null || exit 0; sleep 0.1; done; exit 1`)
		s.compose(t, "unpause", "registry")
		s.server(t, `flock -w 60 `+srvDir+`/.lock true`)
		s.wantServing(t, v4)
		if env := s.server(t, "cat "+srvDir+"/.env"); !strings.Contains(env, "FRICT_DIGEST="+v4+"\n") {
			t.Errorf(".env = %q, want %s", env, v4)
		}
	})

	t.Run("migrated schema: going back fails loudly and the backup restores it", func(t *testing.T) {
		out, ok := s.deploy(t, migrates)
		if ok || !strings.Contains(out, "SERVER IS DOWN: going back to "+v4+" failed too") || !strings.Contains(out, "refuses the newer schema") {
			t.Fatalf("ok=%v, want a failure that says the server is down because of the schema", ok)
		}
		if got := s.healthz(t); got == "200" {
			t.Errorf("/healthz = 200 though the deploy said the server is down")
		}
		backup := regexp.MustCompile(`backups/\S+\.tar`).FindString(out)
		s.server(t, restoreCommands(t, filepath.Base(backup)))
		s.wantServing(t, v4)
		s.server(t, "grep -aq "+enrolled+" "+srvDir+"/data/frict.db")
	})

	t.Run("the installer converges a server set up by hand and keeps it serving", func(t *testing.T) {
		pub := s.workstation(t, "ssh-keygen -y -f /root/DEPLOY_SSH_KEY")
		s.server(t, `cd /srv/frict
docker compose down
cd /
userdel --remove frict-deploy
for p in /srv/frict /usr/local/bin/frict-deploy /etc/sudoers.d/frict-deploy; do rm -rf "${p:?}"; done
old=$(mktemp -d)
mkdir "$old/deploy"
for f in frict-deploy sudoers compose.yaml; do
  { cat "/src/deploy/$f"; echo '# from an older main'; } > "$old/deploy/$f"
done
cd "$old"
`+handSetup+`
install -o root -g root -m 0600 /dev/stdin /srv/frict/frict.env <<'ENV'
FRICT_API_HOSTNAME=api.frict.app
FRICT_CLIENT_ID=DITEST00000000000000
ENV
printf 'restrict,command="/usr/bin/sudo -n /usr/local/bin/frict-deploy" %s\n' '`+pub+`' > /home/frict-deploy/.ssh/authorized_keys
cd /
rm -rf "${old:?}"`)
		s.mustDeploy(t, v4)
		s.wantServing(t, v4)
		if got := s.installed(t); got == s.fresh {
			t.Fatal("the hand setup matches a fresh install, so the installer has nothing to upgrade")
		}
		kept, containers := s.kept(t), s.containers(t)
		s.mustInstall(t, "")
		if got := s.installed(t); got != s.fresh {
			t.Errorf("installed:\n%s\nwant as after a fresh install:\n%s", got, s.fresh)
		}
		if got := s.kept(t); got != kept {
			t.Errorf("changed:\n--- before\n%s\n--- after\n%s", kept, got)
		}
		if got := s.containers(t); got != containers {
			t.Errorf("containers changed:\n--- before\n%s\n--- after\n%s", containers, got)
		}
		if out := s.mustDeploy(t, v4); !strings.Contains(out, "is already running and healthy. Not restarted.") {
			t.Errorf("deploy after the installer: %s", out)
		}
		s.wantServing(t, v4)
	})
}

// handSetup is docs/deploy.md's server setup before deploy/install.sh, run
// from a directory holding deploy/.
const handSetup = `(
set -e
getent passwd frict-deploy >/dev/null || sudo useradd --create-home --shell /bin/sh frict-deploy
sudo install -d -o root -g root -m 0755 /home/frict-deploy/.ssh
sudo install -o root -g root -m 0755 deploy/frict-deploy /usr/local/bin/frict-deploy
sudo visudo -cqf deploy/sudoers
sudo install -o root -g root -m 0440 deploy/sudoers /etc/sudoers.d/frict-deploy
sudo visudo -cq
sudo install -d -o root -g root -m 0755 /srv/frict
sudo install -o root -g root -m 0644 deploy/compose.yaml /srv/frict/compose.yaml
sudo install -d -o 65532 -g 65532 -m 0700 /srv/frict/data /srv/frict/secrets
)
(
set -e
f=/srv/frict/secrets/duo-client-secret
sudo test -e "$f" || openssl rand -hex 20 | sudo install -o 65532 -g 65532 -m 0400 /dev/stdin "$f"
)`

// docBlock returns the first bash block of docs/deploy.md after a line.
func docBlock(t *testing.T, after string) string {
	t.Helper()
	doc, err := os.ReadFile("../../docs/deploy.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, found := strings.Cut(string(doc), "\n"+after+"\n")
	if !found {
		t.Fatalf("docs/deploy.md has no line %q", after)
	}
	_, block, found := strings.Cut(section, "```bash\n")
	if !found {
		t.Fatalf("docs/deploy.md has no bash block after %q", after)
	}
	block, _, _ = strings.Cut(block, "```")
	return block
}

// restoreCommands returns docs/deploy.md's restore commands for one backup.
func restoreCommands(t *testing.T, backup string) string {
	t.Helper()
	return strings.NewReplacer("<backup>.tar", backup, "sudo ", "").Replace(docBlock(t, "## Restore"))
}
