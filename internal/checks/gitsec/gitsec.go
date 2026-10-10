// Package gitsec scans git history (GIT-001, GIT-002) and staged changes for committed secrets.
package gitsec

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"

	"github.com/zonicisalive/pulp/internal/check"
	"github.com/zonicisalive/pulp/internal/finding"
	"github.com/zonicisalive/pulp/internal/secrets"
)

const maxCommits = 1000 // ponytail: fixed depth cap, make a flag when someone needs deeper history

func init() {
	check.Register(historySecrets{})
	check.Register(envFiles{})
	check.Register(unignoredEnv{})
}

// gitLines streams the stdout lines of `git -C root <args>`; ok=false when root is
// not a repo or git is missing. wait must be called after the stream is consumed.
func gitLines(ctx context.Context, root string, args ...string) (lines func(func(string)), wait func() error, ok bool) {
	if _, err := exec.LookPath("git"); err != nil {
		return nil, nil, false
	}
	if exec.CommandContext(ctx, "git", "-C", root, "rev-parse", "--git-dir").Run() != nil {
		return nil, nil, false
	}
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", root}, args...)...)
	out, err := cmd.StdoutPipe()
	if err != nil || cmd.Start() != nil {
		return nil, nil, false
	}
	return func(fn func(string)) { eachLine(out, fn) }, cmd.Wait, true
}

func logArgs(extra ...string) []string {
	return append([]string{"log", "--all", "--no-color", "--no-ext-diff", fmt.Sprintf("--max-count=%d", maxCommits)}, extra...)
}

// eachLine reads lines, skipping any longer than the buffer (minified blobs).
func eachLine(r io.Reader, fn func(string)) {
	br := bufio.NewReaderSize(r, 1<<16)
	for {
		line, isPrefix, err := br.ReadLine()
		if err != nil {
			return
		}
		if isPrefix {
			for isPrefix && err == nil {
				_, isPrefix, err = br.ReadLine()
			}
			continue
		}
		fn(string(line))
	}
}

var lockFile = regexp.MustCompile(`(\.lock|package-lock\.json|go\.sum|pnpm-lock\.yaml)$`)

// scanDiff turns a unified-diff stream (optionally with "commit <sha>" lines) into
// GIT-001 findings. Each distinct secret is reported once.
func scanDiff(lines func(func(string)), where string) []finding.Finding {
	var out []finding.Finding
	seen := map[string]bool{}
	commit, path, skip := "", "", false
	lines(func(l string) {
		switch {
		case strings.HasPrefix(l, "commit "):
			commit = l[7:]
		case strings.HasPrefix(l, "+++ "):
			path = strings.TrimPrefix(l[4:], "b/")
			skip = lockFile.MatchString(path)
		case !skip && len(l) > 1 && l[0] == '+':
			m, ok := secrets.Scan(l[1:])
			if !ok || seen[m.Name+"|"+m.Value] {
				return
			}
			seen[m.Name+"|"+m.Value] = true
			out = append(out, finding.New(finding.Input{ID: "GIT-001", Severity: finding.Critical, Confidence: m.Confidence,
				Title: m.Name + " " + where, Evidence: m.Value, Secret: true,
				Location:    finding.Location{Path: path, Commit: short(commit)},
				Remediation: "Rotate the credential first, then purge it with git filter-repo."}))
		}
	})
	return out
}

func short(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

// ---- GIT-001 ----

type historySecrets struct{}

func (historySecrets) ID() string       { return "GIT-001" }
func (historySecrets) Category() string { return "git" }
func (historySecrets) Title() string    { return "Secret committed in git history" }

func (c historySecrets) Run(ctx context.Context, env check.Env) ([]finding.Finding, error) {
	lines, wait, ok := gitLines(ctx, env.Root, logArgs("-p", "-U0", "--format=commit %H")...)
	if !ok {
		return nil, nil // not a git repo
	}
	out := scanDiff(lines, "in git history")
	return out, wait()
}

// ---- GIT-002 ----

type envFiles struct{}

func (envFiles) ID() string       { return "GIT-002" }
func (envFiles) Category() string { return "git" }
func (envFiles) Title() string    { return ".env file committed to git history" }

var envPath = regexp.MustCompile(`(^|/)\.env(\.[^/]+)?$`)
var envOK = regexp.MustCompile(`(?i)example|sample|template|dist`)

func isEnvFile(p string) bool { return envPath.MatchString(p) && !envOK.MatchString(p) }

func (c envFiles) Run(ctx context.Context, env check.Env) ([]finding.Finding, error) {
	lines, wait, ok := gitLines(ctx, env.Root, logArgs("--diff-filter=A", "--name-only", "--format=commit %H")...)
	if !ok {
		return nil, nil
	}
	var out []finding.Finding
	seen := map[string]bool{}
	commit := ""
	lines(func(l string) {
		if strings.HasPrefix(l, "commit ") {
			commit = l[7:]
		} else if isEnvFile(l) && !seen[l] {
			seen[l] = true
			out = append(out, envFinding(l, short(commit), c.Title()))
		}
	})
	return out, wait()
}

func envFinding(path, commit, title string) finding.Finding {
	return finding.New(finding.Input{ID: "GIT-002", Severity: finding.High, Title: title,
		Evidence: path, Location: finding.Location{Path: path, Commit: commit},
		Remediation: "Remove from history (git filter-repo), rotate its secrets, add .env to .gitignore."})
}

// ---- GIT-003 ----

type unignoredEnv struct{}

func (unignoredEnv) ID() string       { return "GIT-003" }
func (unignoredEnv) Category() string { return "git" }
func (unignoredEnv) Title() string    { return ".env file exists but is not in .gitignore" }

// Run lists untracked files git does NOT ignore; a .env among them is one `git add .` from being committed.
func (c unignoredEnv) Run(ctx context.Context, env check.Env) ([]finding.Finding, error) {
	lines, wait, ok := gitLines(ctx, env.Root, "ls-files", "--others", "--exclude-standard")
	if !ok {
		return nil, nil
	}
	var out []finding.Finding
	lines(func(l string) {
		if isEnvFile(l) {
			out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: finding.Medium, Confidence: "high", Title: c.Title(),
				Evidence: l, Location: finding.Location{Path: l},
				Remediation: "echo '.env*' >> .gitignore (keep !.env.example if you ship one)."}))
		}
	})
	return out, wait()
}

// Staged scans the index (what the next commit would contain) for secrets and .env files.
// Used by `pulp staged` and the pre-commit hook.
func Staged(ctx context.Context, root string) ([]finding.Finding, error) {
	lines, wait, ok := gitLines(ctx, root, "diff", "--cached", "-U0", "--no-color", "--no-ext-diff")
	if !ok {
		return nil, fmt.Errorf("%s is not a git repository", root)
	}
	out := scanDiff(lines, "in staged changes")
	if err := wait(); err != nil {
		return out, err
	}
	names, wait, _ := gitLines(ctx, root, "diff", "--cached", "--name-only", "--diff-filter=AM")
	names(func(l string) {
		if isEnvFile(l) {
			out = append(out, envFinding(l, "", ".env file staged for commit"))
		}
	})
	return out, wait()
}
