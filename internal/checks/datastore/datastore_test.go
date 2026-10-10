package datastore

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zonicisalive/pulp/internal/check"
	"github.com/zonicisalive/pulp/internal/finding"
)

func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	d := t.TempDir()
	for n, b := range files {
		p := filepath.Join(d, n)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(b), 0o600)
	}
	return d
}

func run(t *testing.T, c check.Check, d string) []finding.Finding {
	t.Helper()
	got, err := c.Run(context.Background(), check.Env{Root: d})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestRedis(t *testing.T) {
	cases := []struct {
		conf string
		want []string // severities
	}{
		{"bind 0.0.0.0\n", []string{"high"}},
		{"bind 127.0.0.1\nprotected-mode no\n", []string{"high"}},
		{"bind 0.0.0.0\nrequirepass s3cretvalue\n", []string{"medium"}},
		{"bind 127.0.0.1 -::1\nprotected-mode yes\n", nil},
		{"# bind 0.0.0.0\n", nil},
		{"user default on >pw ~* +@all\nbind *\n", []string{"medium"}},
	}
	for i, c := range cases {
		got := run(t, redis{}, tree(t, map[string]string{"redis.conf": c.conf}))
		var sev []string
		for _, f := range got {
			sev = append(sev, f.Severity.String())
		}
		if strings.Join(sev, ",") != strings.Join(c.want, ",") {
			t.Errorf("case %d: got %v want %v", i, sev, c.want)
		}
	}
}

func TestMongoMySQL(t *testing.T) {
	d := tree(t, map[string]string{
		"a/mongod.conf": "net:\n  bindIp: 0.0.0.0\n",
		"b/mongod.conf": "net:\n  bindIp: 127.0.0.1\nsecurity:\n  authorization: enabled\n",
		"c/mongod.conf": "net:\n  bindIp: 127.0.0.1\n",
		"my.cnf":        "[mysqld]\nbind-address = 0.0.0.0\nskip-grant-tables\n# local-infile=1\nlocal_infile=1\n",
	})
	m := run(t, mongo{}, d)
	crit, med := 0, 0
	for _, f := range m {
		switch f.Severity {
		case finding.Critical:
			crit++
		case finding.Medium:
			med++
		}
	}
	if len(m) != 2 || crit != 1 || med != 1 {
		t.Errorf("mongo: %+v", m)
	}
	if got := run(t, mysql{}, d); len(got) != 3 {
		t.Errorf("mysql want 3, got %+v", got)
	}
}

func TestComposeStores(t *testing.T) {
	d := tree(t, map[string]string{
		"docker-compose.yml": `services:
  db:
    environment:
      MYSQL_ALLOW_EMPTY_PASSWORD: "yes"
      MYSQL_ROOT_PASSWORD: root
      MONGO_INITDB_ROOT_PASSWORD: ${MONGO_PW}
      REDIS_PASSWORD: 9f8d7c6b5a4e3d2c
    ports:
      - "6379:6379"
      - "127.0.0.1:3306:3306"
      - 27017:27017
    command: redis-server --protected-mode no
`,
	})
	got := run(t, composeStores{}, d)
	// empty-pw, weak root pw, redis port, mongo port, protected-mode
	if len(got) != 5 {
		var s []string
		for _, f := range got {
			s = append(s, f.Title)
		}
		t.Fatalf("want 5, got %d: %v", len(got), s)
	}
	for _, f := range got {
		if strings.Contains(f.Evidence, "=root") || strings.HasSuffix(f.Evidence, ": root") {
			t.Errorf("password evidence must be redacted: %q", f.Evidence)
		}
	}
}
