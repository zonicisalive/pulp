// Package datastore checks Redis, MongoDB, MySQL/MariaDB configs and compose-published data stores.
package datastore

import (
	"context"
	"regexp"
	"strings"

	"github.com/zonicisalive/pulp/internal/check"
	"github.com/zonicisalive/pulp/internal/finding"
	"github.com/zonicisalive/pulp/internal/fsutil"
	"github.com/zonicisalive/pulp/internal/linepat"
)

func init() {
	check.Register(redis{[]string{"/etc/redis/redis.conf", "/etc/redis.conf", "/etc/valkey/valkey.conf"}})
	check.Register(mongo{[]string{"/etc/mongod.conf", "/etc/mongodb.conf"}})
	check.Register(mysql{[]string{"/etc/my.cnf", "/etc/my.cnf.d/*.cnf", "/etc/mysql/my.cnf", "/etc/mysql/*.conf.d/*.cnf", "/etc/mysql/mariadb.conf.d/*.cnf"}})
	check.Register(composeStores{})
}

func re(s string) *regexp.Regexp { return regexp.MustCompile(s) }

func stripComment(l string) string {
	if i := strings.IndexByte(l, '#'); i >= 0 {
		l = l[:i]
	}
	return strings.TrimSpace(l)
}

func add(out *[]finding.Finding, id string, sev finding.Severity, conf, title, path string, line int, ev, fix string) {
	*out = append(*out, finding.New(finding.Input{ID: id, Severity: sev, Confidence: conf, Title: title, Evidence: ev,
		Location: finding.Location{Path: path, Line: line}, Remediation: fix}))
}

// ---- DB-001: Redis ----

type redis struct{ sys []string }

func (redis) ID() string       { return "DB-001" }
func (redis) Category() string { return "db" }
func (redis) Title() string    { return "Redis without password or exposed to the network" }

func (c redis) Run(ctx context.Context, env check.Env) ([]finding.Finding, error) {
	var out []finding.Finding
	files := fsutil.Collect(ctx, env.Root, c.sys, func(n string) bool { return n == "redis.conf" || n == "valkey.conf" })
	for path, lines := range files {
		bindAll, bindLine, protectedOff, protLine, auth := false, 0, false, 0, false
		for i, raw := range lines {
			f := strings.Fields(stripComment(raw))
			if len(f) < 2 {
				continue
			}
			switch strings.ToLower(f[0]) {
			case "bind":
				for _, a := range f[1:] {
					if a == "0.0.0.0" || a == "*" || a == "::" || a == "-::*" {
						bindAll, bindLine = true, i+1
					}
				}
			case "protected-mode":
				if strings.EqualFold(f[1], "no") {
					protectedOff, protLine = true, i+1
				}
			case "requirepass":
				auth = true
			case "user": // ACL: "user default on >secret ~* +@all" sets a password; "nopass" removes it
				if f[1] == "default" && strings.Contains(raw, ">") {
					auth = true
				}
			}
		}
		switch {
		case !auth && (bindAll || protectedOff):
			ln := max(bindLine, protLine)
			add(&out, c.ID(), finding.High, "high", "Redis has no password and accepts remote connections", path, ln, "no requirepass; bind/protected-mode open",
				"Set requirepass (or ACL users), bind 127.0.0.1, keep protected-mode yes.")
		case bindAll:
			add(&out, c.ID(), finding.Medium, "high", "Redis listens on all interfaces", path, bindLine, "bind 0.0.0.0",
				"Bind to 127.0.0.1 or a private interface and firewall the port.")
		}
	}
	return out, nil
}

// ---- DB-002: MongoDB ----

type mongo struct{ sys []string }

func (mongo) ID() string       { return "DB-002" }
func (mongo) Category() string { return "db" }
func (mongo) Title() string    { return "MongoDB authentication disabled or exposed" }

var (
	mongoBindAll = re(`(?m)^\s*(bindIp\s*:.*(0\.0\.0\.0|::)|bindIpAll\s*:\s*true)`)
	mongoAuthOn  = re(`(?m)^\s*authorization\s*:\s*["']?enabled`)
)

func (c mongo) Run(ctx context.Context, env check.Env) ([]finding.Finding, error) {
	var out []finding.Finding
	for path, lines := range fsutil.Collect(ctx, env.Root, c.sys, func(n string) bool { return n == "mongod.conf" || n == "mongodb.conf" }) {
		text := strings.Join(lines, "\n")
		bindAll, auth := mongoBindAll.MatchString(text), mongoAuthOn.MatchString(text)
		switch {
		case bindAll && !auth:
			add(&out, c.ID(), finding.Critical, "high", "MongoDB is open to the network with authentication disabled", path, 0, "bindIp all, no authorization",
				"Enable security.authorization and bind to 127.0.0.1.")
		case !auth:
			add(&out, c.ID(), finding.Medium, "medium", "MongoDB authentication is not enabled (any local process can read all data)", path, 0, "no security.authorization: enabled",
				"Set security.authorization: enabled and create users.")
		case bindAll:
			add(&out, c.ID(), finding.Medium, "high", "MongoDB listens on all interfaces", path, 0, "bindIp all", "Bind to 127.0.0.1 or a private interface.")
		}
	}
	return out, nil
}

// ---- DB-003: MySQL / MariaDB ----

type mysql struct{ sys []string }

func (mysql) ID() string       { return "DB-003" }
func (mysql) Category() string { return "db" }
func (mysql) Title() string    { return "MySQL/MariaDB insecure server option" }

var mysqlPats = []linepat.Pat{
	{Re: re(`(?i)^\s*skip[-_]grant[-_]tables\b`), Sev: finding.Critical, Confidence: "high",
		Title: "skip-grant-tables disables ALL authentication", Fix: "Remove it; reset the root password the normal way."},
	{Re: re(`(?i)^\s*bind[-_]address\s*=\s*(0\.0\.0\.0|\*|::)`), Sev: finding.Medium, Confidence: "high",
		Title: "MySQL listens on all interfaces", Fix: "bind-address = 127.0.0.1"},
	{Re: re(`(?i)^\s*local[-_]infile\s*=\s*(1|on|true)`), Sev: finding.Low,
		Title: "local_infile enabled (lets a malicious server read client files)", Fix: "local_infile = 0"},
}

func (c mysql) Run(ctx context.Context, env check.Env) ([]finding.Finding, error) {
	var out []finding.Finding
	for path, lines := range fsutil.Collect(ctx, env.Root, c.sys, func(n string) bool { return n == "my.cnf" || n == "mysqld.cnf" }) {
		for i, l := range lines {
			t := stripComment(l)
			for _, p := range mysqlPats {
				if p.Re.MatchString(t) {
					add(&out, c.ID(), p.Sev, p.Confidence, p.Title, path, i+1, t, p.Fix)
					break
				}
			}
		}
	}
	return out, nil
}

// ---- DB-004: compose-published data stores & weak credentials ----

type composeStores struct{}

func (composeStores) ID() string       { return "DB-004" }
func (composeStores) Category() string { return "db" }
func (composeStores) Title() string {
	return "Compose publishes a data store or sets empty/weak credentials"
}

const weak = `(root|password|admin|123456|12345678|secret|changeme|pass|test|mysql|mongo|redis|toor)?`

var composePats = []linepat.Pat{
	{Re: re(`(?i)\b(MYSQL_ALLOW_EMPTY_PASSWORD|ALLOW_EMPTY_PASSWORD)\b["']?\s*[:=]\s*["']?(yes|1|true)`), Sev: finding.High, Confidence: "high",
		Title: "Database container allows an empty root password", Fix: "Set a strong password from a secret."},
	{Re: re(`(?i)\b(MYSQL_ROOT_PASSWORD|MYSQL_PASSWORD|MARIADB_ROOT_PASSWORD|MONGO_INITDB_ROOT_PASSWORD|REDIS_PASSWORD)\b["']?\s*[:=]\s*["']?` + weak + `["']?\s*(#.*)?$`),
		Sev: finding.High, Secret: true, Title: "Database container uses an empty or default password", Fix: "Use a long random password from a secret store."},
	{Re: re(`redis-server\b.*--protected-mode\s+no`), Sev: finding.High, Confidence: "high",
		Title: "Redis started with protected-mode off", Fix: "Remove the flag and set --requirepass."},
	{Re: re(`^\s*-\s*["']?(?:(?:0\.0\.0\.0:)?\d+:|\d+:)(6379|27017|3306|9200|9300|11211|5984|1433|9042)(/tcp)?["']?\s*$`), Sev: finding.Medium, Confidence: "high",
		Title: "Data store port published on all host interfaces", Fix: `Bind to loopback: "127.0.0.1:<host>:<container>".`},
}

func (c composeStores) Run(ctx context.Context, env check.Env) ([]finding.Finding, error) {
	match := func(n string) bool {
		return fsutil.ComposeName.MatchString(n) || n == ".env" || strings.HasPrefix(n, ".env.")
	}
	return linepat.Scan(ctx, env.Root, c.ID(), match, composePats, linepat.Opts{Comment: "#"}), nil
}
