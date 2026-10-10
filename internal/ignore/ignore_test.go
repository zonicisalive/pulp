package ignore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zonicisalive/pulp/internal/finding"
)

func mk(id, path, commit string) finding.Finding {
	return finding.New(finding.Input{ID: id, Title: "t", Evidence: path + commit, Location: finding.Location{Path: path, Commit: commit}})
}

func TestRules(t *testing.T) {
	d := t.TempDir()
	byFP := mk("PG-003", "a/.env", "")
	p := filepath.Join(d, ".pulp-ignore")
	os.WriteFile(p, []byte("# comment\n"+byFP.Fingerprint+" # reason\nCORS-001 demo/*\nGIT-001 commit:e0cc9\nDOCK-003\n"), 0o600)
	s := Load(p, filepath.Join(d, "missing"))
	cases := []struct {
		f    finding.Finding
		want bool
	}{
		{byFP, true},
		{mk("CORS-001", "demo/app.js", ""), true},
		{mk("CORS-001", "src/app.js", ""), false},
		{mk("GIT-001", "x.go", "e0cc948"), true},
		{mk("GIT-001", "x.go", "aaaaaaa"), false},
		{mk("GIT-001", "x.go", ""), false},
		{mk("DOCK-003", "any", ""), true},
		{mk("PG-003", "b/.env", ""), false},
	}
	for i, c := range cases {
		if got := s.Match(c.f); got != c.want {
			t.Errorf("case %d (%s %s): got %v", i, c.f.ID, c.f.Location.Path, got)
		}
	}
	kept, n := s.Filter([]finding.Finding{byFP, mk("X-1", "z", "")})
	if len(kept) != 1 || n != 1 {
		t.Errorf("filter: kept=%d suppressed=%d", len(kept), n)
	}
}

func TestAppendIdempotent(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".pulp-ignore")
	f := mk("PG-003", ".env", "")
	f.Evidence = "SECRETVALUE"
	if n, _ := Append(p, []finding.Finding{f}); n != 1 {
		t.Fatal("first append must add 1")
	}
	if n, _ := Append(p, []finding.Finding{f}); n != 0 {
		t.Fatal("second append must add 0")
	}
	b, _ := os.ReadFile(p)
	if strings.Contains(string(b), "SECRETVALUE") {
		t.Error("evidence leaked into ignore file")
	}
}
