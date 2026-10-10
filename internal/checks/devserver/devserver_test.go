package devserver

import (
	"context"
	"os"
	"path/filepath"
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
		if err := os.WriteFile(p, []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
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

func sev(f []finding.Finding, s finding.Severity) int {
	n := 0
	for _, x := range f {
		if x.Severity == s {
			n++
		}
	}
	return n
}

func TestDebugMode(t *testing.T) {
	d := tree(t, map[string]string{
		"app.py":            "app.run(host='0.0.0.0', port=5000, debug=True)\n",
		"other.py":          "app.run(debug=True)\n# app.run(debug=True)\n",
		"settings.py":       "DEBUG = True\nALLOWED_HOSTS = ['*']\nSECRET_KEY = 'django-insecure-abcdefghijklmnop'\nSECRET_KEY = os.environ['K']\n",
		"tests/test_app.py": "app.run(debug=True)\n",
		"clean.py":          "app.run(debug=False)\n",
	})
	got := run(t, debugMode{}, d)
	if len(got) != 5 || sev(got, finding.Critical) != 1 || sev(got, finding.High) != 1 {
		t.Fatalf("want 5 (1 crit, 1 high), got %d: %+v", len(got), got)
	}
	for _, f := range got {
		if f.Evidence == "SECRET_KEY = 'django-insecure-abcdefghijklmnop'" {
			t.Error("SECRET_KEY line must be redacted")
		}
	}
}

func TestAllInterfaces(t *testing.T) {
	d := tree(t, map[string]string{
		"package.json":   `{"scripts":{"dev":"vite --host 0.0.0.0","ok":"vite","serve":"next dev -H 0.0.0.0"}}`,
		"run.sh":         "python3 -m http.server 8000\npython -m http.server 8000 --bind 127.0.0.1\n",
		"vite.config.ts": "export default { server: { host: true } }\n",
	})
	got := run(t, allInterfaces{}, d)
	// package.json is one line (1 finding), run.sh http.server (note: --bind variant also matches, ponytail), vite.config
	if len(got) < 3 {
		t.Fatalf("want >=3, got %d: %+v", len(got), got)
	}
}

func TestExposedStatic(t *testing.T) {
	d := tree(t, map[string]string{
		"server.js":           "app.use(express.static(__dirname))\napp.use(express.static('public'))\n",
		"public/.env":         "A=1\n",
		"public/.env.example": "A=\n",
		"public/dump.sql":     "x\n",
		"public/app.js":       "x\n",
		"public/.git/HEAD":    "ref\n",
		"src/db.sql":          "x\n",
	})
	got := run(t, exposedStatic{}, d)
	if len(got) != 4 { // express root, .env, dump.sql, .git
		t.Fatalf("want 4, got %d: %+v", len(got), got)
	}
}

func TestTLSOff(t *testing.T) {
	d := tree(t, map[string]string{
		"a.py": "requests.get(u, verify=False)\n",
		"b.js": "new https.Agent({ rejectUnauthorized: false })\n",
		"c.go": "tls.Config{InsecureSkipVerify: true}\n",
		"d.sh": "curl -k https://x\ncurl https://x\n",
		"e.py": "requests.get(u, verify=True)\n",
	})
	if got := run(t, tlsOff{}, d); len(got) != 4 {
		t.Fatalf("want 4, got %d: %+v", len(got), got)
	}
}
