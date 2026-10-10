package gitsec

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zonicisalive/pulp/internal/check"
)

func git(t *testing.T, d string, args ...string) {
	t.Helper()
	a := append([]string{"-C", d, "-c", "user.name=t", "-c", "user.email=t@t"}, args...)
	if out, err := exec.Command("git", a...).CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
}

func TestGitHistory(t *testing.T) {
	d := t.TempDir()
	git(t, d, "init", "-q")
	// built at runtime so this file does not trip scanners on pulp's own repo
	key := "AKIA" + "ABCDEFGHIJKLMNOP"
	os.WriteFile(filepath.Join(d, "cfg.js"), []byte("const k = '"+key+"'\n"), 0o600)
	os.WriteFile(filepath.Join(d, "docs.md"), []byte("AKIA"+"IOSFODNN7EXAMPLE\n"), 0o600)                      // doc placeholder: ignored
	os.WriteFile(filepath.Join(d, "app.js"), []byte("const API_KEY = 'PASTE_YOUR_API_KEY_HERE_NOW'\n"), 0o600) // placeholder: ignored
	os.WriteFile(filepath.Join(d, ".env"), []byte("X=1\n"), 0o600)
	os.WriteFile(filepath.Join(d, ".env.example"), []byte("X=\n"), 0o600)
	git(t, d, "add", "-A")
	git(t, d, "commit", "-q", "-m", "add")
	// secret removed from the tree, still in history
	os.WriteFile(filepath.Join(d, "cfg.js"), []byte("const k = process.env.K\n"), 0o600)
	git(t, d, "commit", "-q", "-am", "remove")

	got, err := historySecrets{}.Run(context.Background(), check.Env{Root: d})
	if err != nil || len(got) != 1 {
		t.Fatalf("GIT-001 want 1 finding, got %d err=%v", len(got), err)
	}
	if strings.Contains(got[0].Evidence, key) || got[0].Evidence != "AK****OP" {
		t.Errorf("evidence not redacted: %q", got[0].Evidence)
	}
	envs, _ := envFiles{}.Run(context.Background(), check.Env{Root: d})
	if len(envs) != 1 || envs[0].Location.Path != ".env" {
		t.Errorf("GIT-002 want only .env, got %+v", envs)
	}
	if got, _ := (historySecrets{}).Run(context.Background(), check.Env{Root: t.TempDir()}); got != nil {
		t.Error("non-repo must yield nothing")
	}
}

func TestUnignoredEnv(t *testing.T) {
	d := t.TempDir()
	git(t, d, "init", "-q")
	os.WriteFile(filepath.Join(d, ".env"), []byte("A=1\n"), 0o600)
	os.WriteFile(filepath.Join(d, ".env.local"), []byte("A=1\n"), 0o600)
	os.WriteFile(filepath.Join(d, ".env.example"), []byte("A=\n"), 0o600)
	os.WriteFile(filepath.Join(d, ".gitignore"), []byte(".env.local\n"), 0o600)
	got, _ := unignoredEnv{}.Run(context.Background(), check.Env{Root: d})
	if len(got) != 1 || got[0].Location.Path != ".env" {
		t.Fatalf("want only .env (local ignored, example allowed), got %+v", got)
	}
}
