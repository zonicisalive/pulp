//go:build linux

// Package postgres holds local Postgres misconfiguration checks.
package postgres

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/zonicisalive/pulp/internal/check"
	"github.com/zonicisalive/pulp/internal/finding"
	"github.com/zonicisalive/pulp/internal/fsutil"
)

// System locations of Postgres config on common Linux layouts.
var sysDirs = []string{"/etc/postgresql/*/*", "/var/lib/postgres/data", "/var/lib/pgsql/data", "/var/lib/postgresql/data"}

func init() {
	check.Register(pg001{sysDirs})
	check.Register(pg002{sysDirs})
	check.Register(pg003{})
}

// systemFiles resolves <dir>/<name> for each glob that exists and is readable.
func systemFiles(dirs []string, name string) map[string][]string {
	out := map[string][]string{}
	for _, d := range dirs {
		m, _ := filepath.Glob(filepath.Join(d, name))
		for _, p := range m {
			if lines, ok := fsutil.ReadLines(p); ok {
				out[p] = lines
			}
		}
	}
	return out
}

// configFiles returns system files plus matching files found under the scan root.
func configFiles(ctx context.Context, dirs []string, root, name string) map[string][]string {
	out := systemFiles(dirs, name)
	fsutil.Files(ctx, root, func(n string) bool { return n == name }, func(rel string, lines []string) {
		out[rel] = lines
	})
	return out
}

func stripComment(l string) string {
	if i := strings.IndexByte(l, '#'); i >= 0 {
		l = l[:i]
	}
	return strings.TrimSpace(l)
}

// ---- PG-001: pg_hba.conf trust / open to the world ----

type pg001 struct{ dirs []string }

func (pg001) ID() string       { return "PG-001" }
func (pg001) Category() string { return "postgres" }
func (pg001) Title() string    { return "pg_hba.conf allows trust auth or world-open access" }

var hbaMethods = map[string]bool{"trust": true, "reject": true, "md5": true, "password": true, "scram-sha-256": true,
	"gss": true, "sspi": true, "ident": true, "peer": true, "pam": true, "ldap": true, "radius": true, "cert": true, "bsd": true}

func worldOpen(addr string) bool { return addr == "0.0.0.0/0" || addr == "::/0" || addr == "all" }

func (c pg001) Run(ctx context.Context, env check.Env) ([]finding.Finding, error) {
	var out []finding.Finding
	for path, lines := range configFiles(ctx, c.dirs, env.Root, "pg_hba.conf") {
		for i, raw := range lines {
			f := strings.Fields(stripComment(raw))
			if len(f) < 4 {
				continue
			}
			method := ""
			for _, v := range f[3:] {
				if hbaMethods[v] {
					method = v
					break
				}
			}
			isLocal := f[0] == "local"
			addr := ""
			if !isLocal {
				addr = f[3]
			}
			sev, title := finding.Severity(-1), ""
			switch {
			case method == "trust" && !isLocal && worldOpen(addr):
				sev, title = finding.Critical, "trust auth (no password) open to any address"
			case method == "trust" && !isLocal:
				sev, title = finding.High, "trust auth (no password) for network connections"
			case method == "trust":
				sev, title = finding.Medium, "trust auth on local socket (any local user can connect)"
			case !isLocal && method != "" && method != "reject" && (addr == "0.0.0.0/0" || addr == "::/0"):
				sev, title = finding.Medium, "pg_hba rule accepts connections from any address"
			}
			if sev < 0 {
				continue
			}
			out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: sev, Title: title,
				Evidence: strings.TrimSpace(raw), Location: finding.Location{Path: path, Line: i + 1},
				Remediation: "Use scram-sha-256 and restrict addresses to 127.0.0.1/32 (or a specific subnet)."}))
		}
	}
	return out, nil
}

// ---- PG-002: listen on all interfaces / published 5432 ----

type pg002 struct{ dirs []string }

func (pg002) ID() string       { return "PG-002" }
func (pg002) Category() string { return "postgres" }
func (pg002) Title() string    { return "Postgres listens on all interfaces or publishes 5432 publicly" }

var (
	listenRe = regexp.MustCompile(`^\s*listen_addresses\s*=\s*'?([^'#\s]*)'?`)
	portRe   = regexp.MustCompile(`^\s*-\s*["']?(?:(\d{1,3}(?:\.\d{1,3}){3}):)?5432:5432["']?`)
)

func (c pg002) Run(ctx context.Context, env check.Env) ([]finding.Finding, error) {
	var out []finding.Finding
	for path, lines := range configFiles(ctx, c.dirs, env.Root, "postgresql.conf") {
		for i, l := range lines {
			if m := listenRe.FindStringSubmatch(l); m != nil && (m[1] == "*" || m[1] == "0.0.0.0") {
				out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: finding.Medium,
					Title: "listen_addresses accepts connections on all interfaces", Evidence: strings.TrimSpace(l),
					Location:    finding.Location{Path: path, Line: i + 1},
					Remediation: "Set listen_addresses = 'localhost' unless remote access is required."}))
			}
		}
	}
	fsutil.Files(ctx, env.Root, fsutil.ComposeName.MatchString, func(rel string, lines []string) {
		for i, l := range lines {
			if m := portRe.FindStringSubmatch(l); m != nil && (m[1] == "" || m[1] == "0.0.0.0") {
				out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: finding.Medium,
					Title: "Compose publishes Postgres 5432 on all host interfaces", Evidence: strings.TrimSpace(l),
					Location:    finding.Location{Path: rel, Line: i + 1},
					Remediation: `Bind to loopback: "127.0.0.1:5432:5432".`}))
			}
		}
	})
	return out, nil
}

// ---- PG-003: default / weak credentials in env + compose files ----

type pg003 struct{}

func (pg003) ID() string       { return "PG-003" }
func (pg003) Category() string { return "postgres" }
func (pg003) Title() string    { return "Default or weak Postgres credentials in config" }

var (
	envName  = regexp.MustCompile(`^\.env(\..+)?$`)
	passRe   = regexp.MustCompile(`(?i)\bPOSTGRES_PASSWORD\b["']?\s*[:=]\s*["']?([^"'\s#]*)`)
	urlRe    = regexp.MustCompile(`postgres(?:ql)?://[^:/\s@]+:([^@\s]+)@`)
	weakPass = map[string]bool{"": true, "postgres": true, "password": true, "admin": true, "root": true,
		"123456": true, "12345678": true, "secret": true, "changeme": true, "pass": true, "test": true}
)

func isExample(n string) bool {
	n = strings.ToLower(n)
	return strings.Contains(n, "example") || strings.Contains(n, "sample") || strings.Contains(n, "template")
}

func (c pg003) Run(ctx context.Context, env check.Env) ([]finding.Finding, error) {
	var out []finding.Finding
	match := func(n string) bool {
		return (envName.MatchString(n) || fsutil.ComposeName.MatchString(n)) && !isExample(n)
	}
	fsutil.Files(ctx, env.Root, match, func(rel string, lines []string) {
		for i, l := range lines {
			if strings.HasPrefix(strings.TrimSpace(l), "#") {
				continue
			}
			var pw string
			if m := passRe.FindStringSubmatch(l); m != nil {
				pw = m[1]
			} else if m := urlRe.FindStringSubmatch(l); m != nil {
				pw = m[1]
			} else {
				continue
			}
			if strings.HasPrefix(pw, "$") || !weakPass[strings.ToLower(pw)] {
				continue // env var reference or non-default value
			}
			out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: finding.High, Confidence: "medium",
				Title: "Postgres uses a default/weak password", Evidence: strings.TrimSpace(l), Secret: true,
				Location:    finding.Location{Path: rel, Line: i + 1},
				Remediation: "Use a long random password from a secret store; never commit it."}))
		}
	})
	return out, nil
}
