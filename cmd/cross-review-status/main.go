// Command cross-review-status posts the `cross-review` commit status as the
// frict-cross-review GitHub App.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/frict-auth/frict-server/internal/crossreview"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cross-review-status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	repoFlag := fs.String("repo", "", "owner/name (required)")
	sha := fs.String("sha", "", "full 40-hex commit SHA (required)")
	state := fs.String("state", "", "pending, success, failure or error (required)")
	description := fs.String("description", "", "short status description")
	targetURL := fs.String("target-url", "", "link shown next to the status")
	keyFile := fs.String("key-file", "~/.config/frict/cross-review.pem", "App private key (PEM, mode 600)")
	appID := fs.Int64("app-id", 5557312, "GitHub App ID")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %q\n", fs.Args())
		return 2
	}
	if *repoFlag == "" || *sha == "" || *state == "" {
		fmt.Fprintln(stderr, "--repo, --sha and --state are required")
		return 2
	}
	owner, repo, err := crossreview.ParseRepo(*repoFlag)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := crossreview.ValidateSHA(*sha); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := crossreview.ValidateState(*state); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	path, err := expandHome(*keyFile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	key, err := crossreview.LoadKey(path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c := &crossreview.Client{
		BaseURL: "https://api.github.com",
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		AppID:   *appID,
		Key:     key,
		Now:     time.Now,
	}
	created, err := c.PostStatus(ctx, owner, repo, *sha, crossreview.Status{
		State: *state, Description: *description, TargetURL: *targetURL,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "posted %s=%s on %s/%s@%s (status id %d, creator %s)\n",
		created.Context, created.State, owner, repo, *sha, created.ID, created.Creator.Login)
	return 0
}

func expandHome(p string) (string, error) {
	rest, ok := strings.CutPrefix(p, "~/")
	if !ok {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("expanding %s: %w", p, err)
	}
	return filepath.Join(home, rest), nil
}
