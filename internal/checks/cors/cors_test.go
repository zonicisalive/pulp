package cors

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/zonicisalive/pulp/internal/check"
	"github.com/zonicisalive/pulp/internal/finding"
)

func TestCORS(t *testing.T) {
	d := t.TempDir()
	w := func(n, b string) { os.WriteFile(filepath.Join(d, n), []byte(b), 0o600) }
	w("a.js", "app.use(cors())\n")                                           // medium
	w("b.ts", "cors({ origin: '*', credentials: true })\n")                  // high
	w("settings.py", "CORS_ALLOW_ALL_ORIGINS = True\n")                      // medium
	w("api.py", "app.add_middleware(CORSMiddleware, allow_origins=['*'])\n") // medium
	w("ok.js", "cors({ origin: ['https://app.example.com'] })\n// cors()\n") // clean
	got, _ := cors001{}.Run(context.Background(), check.Env{Root: d})
	if len(got) != 4 {
		t.Fatalf("want 4, got %d: %+v", len(got), got)
	}
	high := 0
	for _, f := range got {
		if f.Severity == finding.High {
			high++
		}
	}
	if high != 1 {
		t.Errorf("want exactly 1 high (credentials), got %d", high)
	}
}
