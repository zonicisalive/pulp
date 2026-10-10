package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/zonicisalive/pulp/internal/checks/gitsec"
)

// staged scans what the next commit would contain. Any finding blocks the commit.
func staged(args []string) int {
	root := "."
	if len(args) > 0 {
		root = args[0]
	}
	fnds, err := gitsec.Staged(context.Background(), root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	fnds, _ = ignoreSet(root).Filter(fnds)
	if len(fnds) == 0 {
		return 0
	}
	table(os.Stderr, fnds, 0, false)
	fmt.Fprintln(os.Stderr, "\ncommit blocked. Remove the secret, or add it to .pulp-ignore, or use `git commit --no-verify`.")
	return 1
}

const hookBody = `#!/bin/sh
# installed by pulp
command -v pulp >/dev/null 2>&1 || exit 0
exec pulp staged
`

func installHook(args []string) int {
	fs := flag.NewFlagSet("install-hook", flag.ContinueOnError)
	force := fs.Bool("force", false, "overwrite an existing pre-commit hook")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	root := "."
	if fs.NArg() > 0 {
		root = fs.Arg(0)
	}
	out, err := exec.Command("git", "-C", root, "rev-parse", "--git-path", "hooks/pre-commit").Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: not a git repository:", root)
		return 2
	}
	p := strings.TrimSpace(string(out))
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, p)
	}
	if b, err := os.ReadFile(p); err == nil && !*force && !strings.Contains(string(b), "pulp staged") {
		fmt.Fprintf(os.Stderr, "error: %s already exists; re-run with --force to overwrite\n", p)
		return 2
	}
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(hookBody), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	fmt.Println("installed", p)
	return 0
}
