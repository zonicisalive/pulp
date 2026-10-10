//go:build linux

package docker

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/zonicisalive/pulp/internal/check"
)

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDock002(t *testing.T) {
	d := t.TempDir()
	bad := write(t, d, "bad.json", `{"hosts":["unix:///var/run/docker.sock","tcp://0.0.0.0:2375"]}`)
	tls := write(t, d, "tls.json", `{"hosts":["tcp://0.0.0.0:2376"],"tls":true}`)
	// 0.0.0.0:2375 LISTEN (0947 = 2375)
	net := write(t, d, "tcp", "  sl  local_address rem_address   st\n   0: 00000000:0947 00000000:0000 0A 0 0\n")
	idle := write(t, d, "tcp-idle", "  sl  local_address rem_address   st\n   0: 00000000:0050 00000000:0000 0A 0 0\n")

	if got, _ := (dock002{bad, []string{idle}}).Run(context.Background(), check.Env{}); len(got) != 1 {
		t.Errorf("tcp host without tls: %+v", got)
	}
	if got, _ := (dock002{tls, []string{idle}}).Run(context.Background(), check.Env{}); len(got) != 0 {
		t.Errorf("tls host must be clean: %+v", got)
	}
	if got, _ := (dock002{d + "/none.json", []string{net}}).Run(context.Background(), check.Env{}); len(got) != 1 {
		t.Errorf("listener on 2375: %+v", got)
	}
}

func TestDock003(t *testing.T) {
	d := t.TempDir()
	write(t, d, "docker-compose.yml", "services:\n  a:\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n  # privileged: true\n")
	write(t, d, "other.yml", "volumes: [/var/run/docker.sock]\n")
	got, err := dock003{}.Run(context.Background(), check.Env{Root: d})
	if err != nil || len(got) != 2 {
		t.Fatalf("want 2 findings (comment + non-compose ignored), got %d %v", len(got), err)
	}
}
