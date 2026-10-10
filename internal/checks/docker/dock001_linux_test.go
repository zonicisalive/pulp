//go:build linux

package docker

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/zonicisalive/pulp/internal/check"
	"github.com/zonicisalive/pulp/internal/finding"
)

func TestDock001(t *testing.T) {
	p := filepath.Join(t.TempDir(), "docker.sock")
	os.WriteFile(p, nil, 0o600)
	cases := []struct {
		mode os.FileMode
		want int // -1 = no finding
	}{
		{0o666, int(finding.Critical)},
		{0o664, int(finding.High)},
		{0o660, -1}, // group = test user's gid, so only mode matters below
	}
	for _, c := range cases {
		os.Chmod(p, c.mode)
		got, err := dock001{p}.Run(context.Background(), check.Env{})
		if err != nil {
			t.Fatal(err)
		}
		if c.want >= 0 && (len(got) != 1 || int(got[0].Severity) != c.want) {
			t.Errorf("mode %o: got %+v", c.mode, got)
		}
	}
	if got, _ := (dock001{p + ".missing"}).Run(context.Background(), check.Env{}); got != nil {
		t.Error("missing socket must yield no findings")
	}
}

func TestRedact(t *testing.T) {
	if got := finding.Redact("AKIAIOSFODNN7EXAMPLE"); got != "AK****LE" {
		t.Error(got)
	}
}
