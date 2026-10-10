//go:build linux

package postgres

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zonicisalive/pulp/internal/check"
)

func put(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPG001(t *testing.T) {
	d := t.TempDir()
	put(t, d, "pg_hba.conf", `# comment
local all all trust
host all all 127.0.0.1/32 scram-sha-256
host all all 10.0.0.0/8 trust
host all all 0.0.0.0/0 trust
host all all 0.0.0.0/0 md5
host all all 0.0.0.0/0 reject
`)
	got, _ := pg001{}.Run(context.Background(), check.Env{Root: d})
	if len(got) != 4 { // local trust, net trust, world trust, world md5
		t.Fatalf("want 4 findings, got %d: %+v", len(got), got)
	}
}

func TestPG002(t *testing.T) {
	d := t.TempDir()
	put(t, d, "postgresql.conf", "listen_addresses = '*'\n")
	put(t, d, "docker-compose.yml", "ports:\n  - \"5432:5432\"\n  - \"127.0.0.1:5432:5432\"\n")
	got, _ := pg002{}.Run(context.Background(), check.Env{Root: d})
	if len(got) != 2 {
		t.Fatalf("want 2 findings (conf + public port), got %d: %+v", len(got), got)
	}
}

func TestPG003(t *testing.T) {
	d := t.TempDir()
	put(t, d, ".env", "POSTGRES_PASSWORD=postgres\nDATABASE_URL=postgres://app:s3cr3t-long-random@db/x\nOTHER=${POSTGRES_PASSWORD}\n")
	put(t, d, ".env.example", "POSTGRES_PASSWORD=postgres\n")
	put(t, d, "docker-compose.yml", "environment:\n  POSTGRES_PASSWORD: password\n  POSTGRES_PASSWORD: ${PW}\n")
	got, _ := pg003{}.Run(context.Background(), check.Env{Root: d})
	if len(got) != 2 {
		t.Fatalf("want 2 findings, got %d: %+v", len(got), got)
	}
	for _, f := range got {
		if strings.Contains(f.Evidence, "=postgres") || strings.Contains(f.Evidence, "s3cr3t") {
			t.Errorf("evidence must be redacted: %q", f.Evidence)
		}
	}
}
