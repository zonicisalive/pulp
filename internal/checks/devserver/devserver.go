// Package devserver flags dev-framework settings that become vulnerabilities when shipped or shared.
package devserver

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/zonicisalive/pulp/internal/check"
	"github.com/zonicisalive/pulp/internal/finding"
	"github.com/zonicisalive/pulp/internal/fsutil"
	"github.com/zonicisalive/pulp/internal/linepat"
)

func init() {
	check.Register(debugMode{})
	check.Register(allInterfaces{})
	check.Register(exposedStatic{})
	check.Register(tlsOff{})
}

func re(s string) *regexp.Regexp { return regexp.MustCompile(s) }

var codeFiles = linepat.Names(nil, []string{".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rb", ".php"})

// ---- DEV-001: debug mode & weak framework settings ----

type debugMode struct{}

func (debugMode) ID() string       { return "DEV-001" }
func (debugMode) Category() string { return "devserver" }
func (debugMode) Title() string    { return "Framework debug mode or insecure default enabled" }

var debugPats = []linepat.Pat{
	{Re: re(`\.run\(.*(host\s*=\s*['"]0\.0\.0\.0['"].*debug\s*=\s*True|debug\s*=\s*True.*host\s*=\s*['"]0\.0\.0\.0['"])`), Sev: finding.Critical,
		Title: "Flask debugger exposed on all interfaces (Werkzeug console = remote code execution)",
		Fix:   "Never run debug=True with host 0.0.0.0. Use `flask run` locally and gunicorn in production."},
	{Re: re(`\.run\(.*debug\s*=\s*True`), Sev: finding.Medium,
		Title: "Flask app.run(debug=True): Werkzeug debugger on if this reaches a server",
		Fix:   "Read debug from an env var that defaults to off."},
	{Re: re(`^\s*DEBUG\s*=\s*True\b`), Sev: finding.Medium,
		Title: "DEBUG = True in settings (leaks stack traces, settings and SQL)",
		Fix:   "Set DEBUG from the environment and default it to False."},
	{Re: re(`^\s*ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]\s*\]`), Sev: finding.Medium,
		Title: "Django ALLOWED_HOSTS = ['*'] allows Host-header attacks",
		Fix:   "List the real hostnames."},
	{Re: re(`^\s*SECRET_KEY\s*=\s*['"][^'"$]{8,}['"]`), Sev: finding.High, Secret: true,
		Title: "Hardcoded Django SECRET_KEY",
		Fix:   "Load SECRET_KEY from the environment and rotate the committed one."},
	{Re: re(`(?i)app\.use\(\s*errorhandler\(`), Sev: finding.Low,
		Title: "Express errorhandler middleware prints stack traces",
		Fix:   "Only enable it when NODE_ENV !== 'production'."},
}

func (c debugMode) Run(ctx context.Context, env check.Env) ([]finding.Finding, error) {
	py := linepat.Scan(ctx, env.Root, c.ID(), linepat.Names(nil, []string{".py"}), debugPats, linepat.Opts{Comment: "#"})
	js := linepat.Scan(ctx, env.Root, c.ID(), linepat.Names(nil, []string{".js", ".ts", ".mjs", ".cjs"}), debugPats[5:], linepat.Opts{Comment: "//"})
	return append(py, js...), nil
}

// ---- DEV-002: dev servers on all interfaces ----

type allInterfaces struct{}

func (allInterfaces) ID() string       { return "DEV-002" }
func (allInterfaces) Category() string { return "devserver" }
func (allInterfaces) Title() string    { return "Dev server or file server bound to all interfaces" }

var ifacePats = []linepat.Pat{
	{Re: re(`python3?\s+-m\s+http\.server\b`), Sev: finding.Medium,
		Title: "python -m http.server serves the current directory to the whole network",
		Fix:   "Add --bind 127.0.0.1."},
	{Re: re(`(vite|next dev|nuxt dev|webpack(-dev-server| serve)|ng serve|astro dev|svelte-kit dev|flask run|php -S|rails s(erver)?)\b.*(--host(=|\s+)(0\.0\.0\.0|::)|--host\s*($|-)|\s-H\s*0\.0\.0\.0|-b\s+0\.0\.0\.0|0\.0\.0\.0:\d+)`), Sev: finding.Medium,
		Title: "Dev server exposed to the local network (anyone on the Wi-Fi can reach it)",
		Fix:   "Bind to localhost; use a tunnel or --host only on trusted networks."},
	{Re: re(`\bhost\s*:\s*(true|['"]0\.0\.0\.0['"])`), Sev: finding.Medium,
		Title: "Dev server config listens on all interfaces",
		Fix:   "Use host: 'localhost' (or 127.0.0.1)."},
}

func (c allInterfaces) Run(ctx context.Context, env check.Env) ([]finding.Finding, error) {
	scripts := linepat.Names([]string{"package.json", "Makefile", "justfile", "Procfile"}, []string{".sh"})
	cfg := func(n string) bool {
		return strings.HasPrefix(n, "vite.config.") || strings.HasPrefix(n, "next.config.") ||
			strings.HasPrefix(n, "nuxt.config.") || strings.HasPrefix(n, "vue.config.") || strings.HasPrefix(n, "webpack.config.")
	}
	out := linepat.Scan(ctx, env.Root, c.ID(), scripts, ifacePats[:2], linepat.Opts{Comment: "#"})
	return append(out, linepat.Scan(ctx, env.Root, c.ID(), cfg, ifacePats[2:], linepat.Opts{Comment: "//"})...), nil
}

// ---- DEV-003: project files served over HTTP ----

type exposedStatic struct{}

func (exposedStatic) ID() string       { return "DEV-003" }
func (exposedStatic) Category() string { return "devserver" }
func (exposedStatic) Title() string    { return "Secrets or source served from a public/static directory" }

var staticRoot = []linepat.Pat{{
	Re: re(`express\.static\(\s*(['"]\.{1,2}/?['"]|__dirname|process\.cwd\(\))\s*[,)]`), Sev: finding.High, Confidence: "high",
	Title: "express.static serves the project root (.env, source and .git become downloadable)",
	Fix:   "Serve a dedicated public/ directory only.",
}}

var publicDir = map[string]bool{"public": true, "static": true, "www": true, "wwwroot": true, "public_html": true}
var riskyFile = re(`(?i)^(\.env(\..+)?|id_rsa|id_ed25519|.*\.(pem|key|sql|bak|sqlite3?|dump|p12|pfx))$`)

func (c exposedStatic) Run(ctx context.Context, env check.Env) ([]finding.Finding, error) {
	out := linepat.Scan(ctx, env.Root, c.ID(), codeFiles, staticRoot, linepat.Opts{Comment: "//"})
	var pubs []string
	fsutil.Walk(ctx, env.Root, func(rel string, d fs.DirEntry) {
		if d.IsDir() && publicDir[d.Name()] {
			pubs = append(pubs, rel)
		}
	})
	for _, pub := range pubs {
		abs := filepath.Join(env.Root, pub)
		if _, err := os.Stat(filepath.Join(abs, ".git")); err == nil {
			out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: finding.High, Confidence: "high",
				Title: "A .git directory sits inside a web-served folder (full source download)", Evidence: filepath.Join(pub, ".git"),
				Location: finding.Location{Path: filepath.Join(pub, ".git")}, Remediation: "Remove it from the web root."}))
		}
		fsutil.Walk(ctx, abs, func(rel string, d fs.DirEntry) {
			name := d.Name()
			if d.IsDir() || !riskyFile.MatchString(name) || strings.Contains(strings.ToLower(name), "example") {
				return
			}
			p := filepath.Join(pub, rel)
			out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: finding.High, Confidence: "medium",
				Title: "Sensitive file inside a web-served folder", Evidence: p, Location: finding.Location{Path: p},
				Remediation: "Move it out of the web root and rotate anything it contains."}))
		})
	}
	return out, nil
}

// ---- DEV-004: TLS verification disabled ----

type tlsOff struct{}

func (tlsOff) ID() string       { return "DEV-004" }
func (tlsOff) Category() string { return "devserver" }
func (tlsOff) Title() string    { return "TLS certificate verification disabled" }

var tlsPats = []linepat.Pat{
	{Re: re(`NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['"]?0`), Sev: finding.Medium, Title: "NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS verification process-wide", Fix: "Remove it; trust the right CA with NODE_EXTRA_CA_CERTS."},
	{Re: re(`rejectUnauthorized\s*:\s*false`), Sev: finding.Medium, Title: "rejectUnauthorized: false disables TLS verification", Fix: "Verify certificates; add your CA instead."},
	{Re: re(`verify\s*=\s*False`), Sev: finding.Medium, Title: "verify=False disables TLS verification (python requests/httpx)", Fix: "Pass verify=<ca bundle path> instead."},
	{Re: re(`InsecureSkipVerify\s*:\s*true`), Sev: finding.Medium, Title: "InsecureSkipVerify: true disables TLS verification (Go)", Fix: "Set RootCAs to your CA pool."},
	{Re: re(`_create_unverified_context`), Sev: finding.Medium, Title: "ssl._create_unverified_context disables TLS verification", Fix: "Use ssl.create_default_context()."},
	{Re: re(`\bcurl\b[^|#]*\s(-k|--insecure)\b`), Sev: finding.Medium, Title: "curl -k / --insecure skips certificate checks", Fix: "Use --cacert with your CA."},
}

func (c tlsOff) Run(ctx context.Context, env check.Env) ([]finding.Finding, error) {
	files := linepat.Names([]string{".env"}, []string{".py", ".js", ".ts", ".mjs", ".cjs", ".go", ".sh", ".yml", ".yaml"})
	return linepat.Scan(ctx, env.Root, c.ID(), files, tlsPats, linepat.Opts{}), nil
}
