package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zonicisalive/pulp/internal/check"
	"github.com/zonicisalive/pulp/internal/explain"
	"github.com/zonicisalive/pulp/internal/report"
)

func git(t *testing.T, d string, args ...string) {
	t.Helper()
	a := append([]string{"-C", d, "-c", "user.name=t", "-c", "user.email=t@t"}, args...)
	if out, err := exec.Command("git", a...).CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
}

// Every registered check must have a `pulp explain` entry, so docs cannot drift.
func TestEveryCheckIsExplained(t *testing.T) {
	for _, c := range check.All() {
		if _, ok := explain.Lookup(c.ID()); !ok {
			t.Errorf("%s has no explain entry", c.ID())
		}
	}
}

// Every check must map to at least one framework control for the compliance report.
func TestEveryCheckHasControls(t *testing.T) {
	for _, c := range check.All() {
		if len(report.Controls[c.ID()]) == 0 {
			t.Errorf("%s has no compliance control mapping", c.ID())
		}
	}
}

func TestHookBlocksStagedSecret(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // keep the user's real ignore file out of the test
	d := t.TempDir()
	git(t, d, "init", "-q")
	if installHook([]string{d}) != 0 {
		t.Fatal("install failed")
	}
	if b, _ := os.ReadFile(filepath.Join(d, ".git/hooks/pre-commit")); !strings.Contains(string(b), "pulp staged") {
		t.Fatal("hook not written")
	}
	if installHook([]string{d}) != 0 { // idempotent
		t.Fatal("re-install must succeed")
	}
	if staged([]string{d}) != 0 {
		t.Fatal("empty index must pass")
	}
	key := "AKIA" + "ABCDEFGHIJKLMNOP"
	os.WriteFile(filepath.Join(d, "a.js"), []byte("k='"+key+"'\n"), 0o600)
	git(t, d, "add", "a.js")
	if staged([]string{d}) != 1 {
		t.Fatal("staged secret must block")
	}
	os.WriteFile(filepath.Join(d, ".pulp-ignore"), []byte("GIT-001 a.js\n"), 0o600)
	if staged([]string{d}) != 0 {
		t.Fatal(".pulp-ignore must unblock")
	}
}

func TestBaselineSilencesScan(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "docker-compose.yml"), []byte("volumes: [/var/run/docker.sock:/var/run/docker.sock]\n"), 0o600)
	if scan([]string{"--skip", "host", d}) != 1 {
		t.Fatal("expected a failing scan before baseline")
	}
	if baseline([]string{d}) != 0 {
		t.Fatal("baseline failed")
	}
	if scan([]string{"--skip", "host", d}) != 0 {
		t.Fatal("baselined findings must not fail the scan")
	}
}
