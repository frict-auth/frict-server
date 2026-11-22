//go:build deploy

// Package deploy runs deploy.yml's own build, push and deploy steps against a
// registry and a box in containers: a real sshd with docs/deploy.md's forced
// command, a real Docker daemon, and frict-deploy as it runs in production.
package deploy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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
)

const (
	imageRepo = "frict-auth/frict-server"
	boxDir    = "/home/deploy/frict"
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
	hosts    string // known_hosts line of the box
	base     int    // app.frict.main-commit of the image the workflow built
	images   []string
}

func (s *stack) compose(t *testing.T, args ...string) string {
	t.Helper()
	return must(t, "", s.env, "docker", append([]string{"compose"}, args...)...)
}

// box runs a root shell script on the box.
func (s *stack) box(t *testing.T, script string) string {
	t.Helper()
	return must(t, script, s.env, "docker", "compose", "exec", "-T", "box", "bash", "-euo", "pipefail", "-s")
}

// ssh runs the ssh client with the deploy key and arbitrary arguments.
func (s *stack) ssh(t *testing.T, args ...string) (string, bool) {
	t.Helper()
	return run(t, "", s.env, "docker", append([]string{"compose", "exec", "-T", "client",
		"ssh", "-F", "/dev/null", "-i", "/root/key", "-o", "BatchMode=yes", "-o", "UserKnownHostsFile=/root/known_hosts", "-o", "ConnectTimeout=10"}, args...)...)
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
	return s.box(t, `cd `+boxDir+`
cat .env
find . -mindepth 1 -not -path './logs*' -not -name .lock -not -path './data/*' -printf '%p %u %m %T@\n' | sort
ls /tmp`) + "\n" + s.containers(t)
}

// containers identifies the box's containers and when they started.
func (s *stack) containers(t *testing.T) string {
	t.Helper()
	return s.box(t, `docker ps --all --quiet | xargs docker inspect --format '{{.Id}} {{.Image}} {{.State.StartedAt}} {{.RestartCount}}'`)
}

// running returns the repository digest of the running container's image.
func (s *stack) running(t *testing.T) string {
	t.Helper()
	return s.box(t, `docker ps --quiet --filter label=com.docker.compose.project=frict | xargs -r docker inspect --format '{{.Image}}' | xargs -r docker image inspect --format '{{join .RepoDigests " "}}'`)
}

func (s *stack) healthz(t *testing.T) string {
	t.Helper()
	return s.box(t, `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8081/healthz || true`)
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
	migrationEdit = [3]string{"internal/store/store.go", "\tCREATE INDEX alerts_by_recipient ON alerts (recipient_user_id, created_at);`,", "\tCREATE INDEX alerts_by_recipient ON alerts (recipient_user_id, created_at);`,\n\t`CREATE TABLE newer (id INTEGER) STRICT;`,"}
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

// up starts the stack and sets the box up as docs/deploy.md does.
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
			out, _ := run(t, "", s.env, "docker", "compose", "exec", "-T", "box", "sh", "-c", "tail -n 100 "+boxDir+"/logs/*")
			t.Logf("box logs:\n%s", out)
		}
		s.compose(t, "down", "--volumes", "--remove-orphans")
		if len(s.images) > 0 {
			must(t, "", nil, "docker", append([]string{"image", "rm", "--no-prune"}, s.images...)...)
		}
	})
	s.compose(t, "up", "--build", "--detach")
	s.registry = s.compose(t, "port", "registry", "443")

	s.key = s.compose(t, "exec", "-T", "client", "sh", "-c", "ssh-keygen -q -t ed25519 -N '' -f /root/key && cat /root/key")
	pub := s.compose(t, "exec", "-T", "client", "cat", "/root/key.pub")
	s.hosts = s.box(t, `printf 'api.frict.app %s' "$(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)"`)
	must(t, s.hosts+"\n", s.env, "docker", "compose", "exec", "-T", "client", "sh", "-c", "cat > /root/known_hosts")

	s.box(t, `for i in $(seq 60); do docker version >/dev/null 2>&1 && break; sleep 0.5; done; docker version >/dev/null
install -o root -g root -m 0755 /deploy/frict-deploy /usr/local/bin/frict-deploy
install -d -o deploy -g deploy -m 0750 `+boxDir+`
install -o root -g root -m 0644 /deploy/compose.yaml `+boxDir+`/compose.yaml
install -d -o 65532 -g 65532 -m 0700 `+boxDir+`/data `+boxDir+`/secrets
printf %s test-client-secret > `+boxDir+`/secrets/duo-client-secret
chown 65532:65532 `+boxDir+`/secrets/duo-client-secret
chmod 0400 `+boxDir+`/secrets/duo-client-secret
install -o deploy -g deploy -m 0600 /dev/stdin `+boxDir+`/frict.env <<'ENV'
FRICT_API_HOSTNAME=api.frict.app
FRICT_CLIENT_ID=DITEST00000000000000
FRICT_AUTHENTIK_URL=https://auth.example
ENV
install -d -o deploy -g deploy -m 0700 ~deploy/.ssh
install -o deploy -g deploy -m 0600 /dev/stdin ~deploy/.ssh/authorized_keys <<'KEY'
`+keyOptions(t)+` `+pub+`
KEY`)
	return s
}

// keyOptions returns docs/deploy.md's authorized_keys options.
func keyOptions(t *testing.T) string {
	t.Helper()
	doc, err := os.ReadFile("../../docs/deploy.md")
	if err != nil {
		t.Fatal(err)
	}
	options := regexp.MustCompile(`printf '(\S+) %s`).FindSubmatch(doc)
	if options == nil {
		t.Fatal("docs/deploy.md has no authorized_keys line")
	}
	return string(options[1])
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
	other := s.push(t, "frict-auth/other", unhealthyDir, "FROM scratch\n"+copyServer+"\n")

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
		uid := s.box(t, `awk '/^Uid:/ {print $2, $3}' /proc/$(docker inspect --format '{{.State.Pid}}' frict-frict-server-1)/status`)
		if uid != "65532 65532" {
			t.Errorf("server process uids = %q, want 65532", uid)
		}
		got := s.box(t, `docker inspect --format '{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}}' frict-frict-server-1`)
		if want := "true [ALL] [no-new-privileges:true]"; got != want {
			t.Errorf("hardening = %s, want %s", got, want)
		}
		listeners := s.box(t, `docker port frict-frict-server-1`)
		if want := "8080/tcp -> 127.0.0.1:8081"; listeners != want {
			t.Errorf("published ports = %q, want %q", listeners, want)
		}
		if out, ok := run(t, "", s.env, "docker", "compose", "exec", "-T", "client", "curl", "-sS", "--max-time", "5", "http://api.frict.app:8081/healthz"); ok || !strings.Contains(out, "curl: (7)") {
			t.Errorf("from another host: ok=%v %q, want no connection", ok, out)
		}
		roots := s.box(t, `docker cp frict-frict-server-1:/etc/ssl/certs/ca-certificates.crt - | tar -xO`)
		if !x509.NewCertPool().AppendCertsFromPEM([]byte(roots)) {
			t.Errorf("the image has no CA certificates to reach FCM with")
		}
	})

	t.Run("refused input changes nothing", func(t *testing.T) {
		before := s.snapshot(t)
		hex := strings.TrimPrefix(v1, "sha256:")
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
			"internal-sftp",
			// Well-formed digests that are not a build of this image.
			"sha256:" + strings.Repeat("0", 64),
			other,
			unlabelled,
		} {
			args := []string{"deploy@api.frict.app"}
			if cmd != "" {
				args = append(args, cmd)
			}
			out, ok := s.ssh(t, args...)
			t.Logf("%q ok=%v %s", cmd, ok, out)
			if ok || !strings.Contains(out, "REFUSED") {
				t.Errorf("%q: ok=%v, want REFUSED: %s", cmd, ok, out)
			}
		}
		if out, ok := s.ssh(t, "-s", "deploy@api.frict.app", "sftp"); ok {
			t.Errorf("sftp: ok=%v, want a failure: %s", ok, out)
		}
		if out, ok := s.ssh(t, "-tt", "deploy@api.frict.app", "sh"); ok || !strings.Contains(out, "PTY allocation request failed") {
			t.Errorf("pty: ok=%v, want no pty: %s", ok, out)
		}
		if out, ok := s.ssh(t, "-W", "127.0.0.1:8081", "deploy@api.frict.app"); ok || !strings.Contains(out, "administratively prohibited") {
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
		env := s.box(t, "cat "+boxDir+"/.env")
		if want := fmt.Sprintf("FRICT_DIGEST=%s\nFRICT_MAIN_COMMIT=%d\nFRICT_PREVIOUS_DIGEST=%s", v1, s.base+2, v0); env != want {
			t.Errorf(".env = %q, want %q", env, want)
		}
		tar := s.box(t, `cd `+boxDir+`/backups; tar --numeric-owner -tvf "$(ls -t | head -1)"`)
		if !regexp.MustCompile(`(?m)^-\S+ 65532/65532 +[1-9]\d* .* data/frict\.db$`).MatchString(tar) {
			t.Errorf("newest backup has no database owned by 65532:\n%s", tar)
		}
	})

	t.Run("redeploying the running digest restarts nothing", func(t *testing.T) {
		before := s.containers(t)
		env := s.box(t, "cat "+boxDir+"/.env")
		s.mustDeploy(t, v1)
		if got := s.box(t, "cat "+boxDir+"/.env"); got != env {
			t.Errorf(".env = %q, want %q", got, env)
		}
		if after := s.containers(t); before != after {
			t.Errorf("containers changed:\n--- before\n%s\n--- after\n%s", before, after)
		}
	})

	t.Run("redeploying the digest of a stopped server starts it", func(t *testing.T) {
		s.box(t, "docker stop frict-frict-server-1")
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
		s.box(t, "mv "+boxDir+"/frict.env "+boxDir+"/frict.env.away")
		out, ok := s.deploy(t, v4)
		s.box(t, "mv "+boxDir+"/frict.env.away "+boxDir+"/frict.env")
		if ok || !strings.Contains(out, "REFUSED") {
			t.Errorf("ok=%v, want a refusal", ok)
		}
		s.wantServing(t, v1)
	})

	t.Run("a healthy container of another digest fails the deploy", func(t *testing.T) {
		s.box(t, "sed -i 's/@\\${FRICT_DIGEST.*/@"+v1+"/' "+boxDir+"/compose.yaml")
		out, ok := s.deploy(t, v4)
		s.box(t, "install -o root -g root -m 0644 /deploy/compose.yaml "+boxDir+"/compose.yaml")
		if ok || !strings.Contains(out, "the running container is not ghcr.io/"+imageRepo+"@"+v4) {
			t.Errorf("ok=%v, want a failure that says which image isn't running", ok)
		}
		s.wantServing(t, v1)
	})

	t.Run("unhealthy build goes back and fails", func(t *testing.T) {
		env := s.box(t, "cat "+boxDir+"/.env")
		out, ok := s.deploy(t, unhealthy)
		if ok || !strings.Contains(out, "/healthz did not answer 200") || !strings.Contains(out, "WENT BACK: ghcr.io/"+imageRepo+"@"+v1) {
			t.Errorf("ok=%v, want a failure that says it went back to %s", ok, v1)
		}
		s.wantServing(t, v1)
		if got := s.box(t, "cat "+boxDir+"/.env"); got != env {
			t.Errorf(".env = %q, want %q", got, env)
		}
		if log := s.box(t, "cat "+boxDir+"/logs/*-server-"+unhealthy[7:19]+".log"); !strings.Contains(log, "store unavailable") {
			t.Errorf("the failed server's log wasn't kept: %q", log)
		}
	})

	t.Run("deploy outlives its SSH connection and refuses a second one", func(t *testing.T) {
		// docker pull waits on the paused registry, so the deploy is under way
		// when its client dies.
		s.compose(t, "pause", "registry")
		ctx, cancel := context.WithCancel(context.Background())
		var out bytes.Buffer
		cmd := exec.CommandContext(ctx, "docker", "compose", "exec", "-T", "client", "ssh", "-F", "/dev/null", "-i", "/root/key",
			"-o", "UserKnownHostsFile=/root/known_hosts", "deploy@api.frict.app", v4)
		cmd.Env, cmd.Stdout, cmd.Stderr = append(os.Environ(), s.env...), &out, &out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		s.box(t, `for i in $(seq 100); do pgrep -f 'docker pull' >/dev/null && exit 0; sleep 0.1; done; exit 1`)
		if out, ok := s.ssh(t, "deploy@api.frict.app", v4); ok || !strings.Contains(out, "another deploy is running") {
			t.Errorf("second deploy: ok=%v %s", ok, out)
		}
		s.compose(t, "exec", "-T", "client", "pkill", "-9", "-x", "ssh")
		cancel()
		cmd.Wait()
		s.box(t, `for i in $(seq 100); do pgrep -f 'sshd: deploy' >/dev/null || exit 0; sleep 0.1; done; exit 1`)
		s.compose(t, "unpause", "registry")
		s.box(t, `flock -w 60 `+boxDir+`/.lock true`)
		s.wantServing(t, v4)
		if env := s.box(t, "cat "+boxDir+"/.env"); !strings.Contains(env, "FRICT_DIGEST="+v4+"\n") {
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
		s.box(t, restoreCommands(t, filepath.Base(backup)))
		s.wantServing(t, v4)
	})
}

// restoreCommands returns docs/deploy.md's restore commands for one backup.
func restoreCommands(t *testing.T, backup string) string {
	t.Helper()
	doc, err := os.ReadFile("../../docs/deploy.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, found := strings.Cut(string(doc), "## Restore")
	if !found {
		t.Fatal("docs/deploy.md has no Restore section")
	}
	_, block, found := strings.Cut(section, "```bash\n")
	if !found {
		t.Fatal("the Restore section has no bash block")
	}
	block, _, _ = strings.Cut(block, "```")
	return strings.NewReplacer("<backup>.tar", backup, "sudo ", "").Replace(block)
}
