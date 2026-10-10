//go:build linux

package host

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/zonicisalive/pulp/internal/check"
	"github.com/zonicisalive/pulp/internal/finding"
	"github.com/zonicisalive/pulp/internal/procnet"
)

type firewallFn func(ctx context.Context) (active, known bool)

func init() {
	check.Register(noFirewall{firewallActive})
	check.Register(openPorts{procnet.Default, firewallActive})
	check.Register(sudoers{[]string{"/etc/sudoers", "/etc/sudoers.d/*"}, sudoList})
	check.Register(debugPorts{"/proc"})
	if home, err := os.UserHomeDir(); err == nil {
		check.Register(browserData{home, "/proc"})
	}
}

// firewallActive asks systemd whether a firewall service runs. known=false when
// there is no systemd, so callers stay silent instead of guessing.
// ponytail: a ruleset loaded outside these services is not seen; add `nft list ruleset` when run as root.
func firewallActive(ctx context.Context) (active, known bool) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false, false
	}
	for _, u := range []string{"ufw", "firewalld", "nftables", "iptables"} {
		out, _ := exec.CommandContext(ctx, "systemctl", "is-active", u).Output()
		if strings.TrimSpace(string(out)) == "active" {
			return true, true
		}
	}
	return false, true
}

// ---- HOST-004: no firewall ----

type noFirewall struct{ fw firewallFn }

func (noFirewall) ID() string       { return "HOST-004" }
func (noFirewall) Category() string { return "host" }
func (noFirewall) Title() string    { return "No active host firewall" }

func (c noFirewall) Run(ctx context.Context, _ check.Env) ([]finding.Finding, error) {
	if active, known := c.fw(ctx); known && !active {
		return []finding.Finding{finding.New(finding.Input{ID: c.ID(), Severity: finding.Medium, Confidence: "medium",
			Title:       "No active firewall service found (ufw, firewalld, nftables, iptables)",
			Location:    finding.Location{Path: "systemd"},
			Remediation: "Enable one, e.g. `sudo systemctl enable --now ufw` after `ufw default deny incoming`."})}, nil
	}
	return nil, nil
}

// ---- HOST-005: data stores listening on all interfaces ----

type openPorts struct {
	procNet []string
	fw      firewallFn
}

func (openPorts) ID() string       { return "HOST-005" }
func (openPorts) Category() string { return "host" }
func (openPorts) Title() string    { return "Database/cache port listening on all interfaces" }

var riskyPorts = map[uint64]string{3306: "mysql", 5432: "postgres", 6379: "redis", 27017: "mongodb",
	9200: "elasticsearch", 11211: "memcached", 5984: "couchdb", 9042: "cassandra", 5900: "vnc", 1433: "mssql"}

func (c openPorts) Run(ctx context.Context, _ check.Env) ([]finding.Finding, error) {
	sev := finding.Medium
	if active, known := c.fw(ctx); known && !active {
		sev = finding.High // nothing filters inbound traffic
	}
	var out []finding.Finding
	seen := map[uint64]bool{}
	for _, l := range procnet.Listeners(c.procNet...) {
		name, risky := riskyPorts[l.Port]
		if !l.AllIfaces || !risky || seen[l.Port] {
			continue
		}
		seen[l.Port] = true
		out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: sev, Confidence: "high",
			Title:       fmt.Sprintf("%s (port %d) accepts connections from every interface", name, l.Port),
			Evidence:    fmt.Sprintf("0.0.0.0:%d LISTEN", l.Port),
			Location:    finding.Location{Path: l.Src},
			Remediation: "Bind the service to 127.0.0.1 (or a unix socket) and/or block the port in the firewall."}))
	}
	return out, nil
}

// ---- HOST-006: sudoers ----

type sudoers struct {
	globs []string
	list  func(ctx context.Context) string // output of `sudo -n -l`
}

func (sudoers) ID() string       { return "HOST-006" }
func (sudoers) Category() string { return "host" }
func (sudoers) Title() string    { return "Passwordless sudo or writable sudoers" }

var nopasswdAll = regexp.MustCompile(`NOPASSWD:\s*ALL\b`)

// sudoList runs `sudo -n -l` (never prompts). Note: sudo logs this call in the auth log.
func sudoList(ctx context.Context) string {
	out, _ := exec.CommandContext(ctx, "sudo", "-n", "-l").Output()
	return string(out)
}

func (c sudoers) Run(ctx context.Context, _ check.Env) ([]finding.Finding, error) {
	var out []finding.Finding
	fileHit := false
	for _, g := range c.globs {
		paths, _ := filepath.Glob(g)
		for _, p := range paths {
			fi, err := os.Stat(p)
			if err != nil || !fi.Mode().IsRegular() {
				continue
			}
			loc := finding.Location{Path: p}
			if fi.Mode().Perm()&0o002 != 0 {
				out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: finding.Critical, Title: "sudoers file is world-writable",
					Evidence: "mode " + fi.Mode().Perm().String(), Location: loc, Remediation: "chmod 0440 " + p}))
			}
			lines, ok := readLines(p) // usually root-only: unreadable is normal
			for i, l := range lines {
				if ok && !strings.HasPrefix(strings.TrimSpace(l), "#") && nopasswdAll.MatchString(l) {
					fileHit = true
					loc := finding.Location{Path: p, Line: i + 1}
					out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: finding.High, Title: "Passwordless sudo for ALL commands",
						Evidence: strings.TrimSpace(l), Location: loc,
						Remediation: "Remove NOPASSWD: ALL; allow only the specific commands that need it."}))
				}
			}
		}
	}
	if !fileHit && nopasswdAll.MatchString(c.list(ctx)) {
		out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: finding.High, Title: "Current user has passwordless sudo for ALL commands",
			Evidence: "sudo -n -l: NOPASSWD: ALL", Location: finding.Location{Path: "sudo -l"},
			Remediation: "Remove NOPASSWD: ALL; allow only the specific commands that need it."}))
	}
	return out, nil
}

func readLines(p string) ([]string, bool) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	return strings.Split(string(b), "\n"), true
}

// procCmdlines returns the argv of every process visible under root (/proc).
func procCmdlines(root string) [][]string {
	var out [][]string
	paths, _ := filepath.Glob(filepath.Join(root, "[0-9]*", "cmdline"))
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
			out = append(out, strings.Split(strings.TrimRight(string(b), "\x00"), "\x00"))
		}
	}
	return out
}

// ---- HOST-007: browser data ----

type browserData struct{ home, proc string }

func (browserData) ID() string       { return "HOST-007" }
func (browserData) Category() string { return "host" }
func (browserData) Title() string    { return "Browser credential store exposed" }

var (
	browserDirs  = []string{".mozilla/firefox", ".config/google-chrome", ".config/chromium", ".config/BraveSoftware", ".config/microsoft-edge"}
	browserFiles = map[string]bool{"Login Data": true, "Cookies": true, "Web Data": true, "logins.json": true, "key4.db": true, "cookies.sqlite": true}
	flagFiles    = []string{".config/chrome-flags.conf", ".config/chromium-flags.conf", ".config/brave-flags.conf"}
)

func (c browserData) Run(_ context.Context, _ check.Env) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, d := range browserDirs {
		root := filepath.Join(c.home, d)
		filepath.WalkDir(root, func(p string, e os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if e.IsDir() {
				if rel, _ := filepath.Rel(root, p); strings.Count(rel, string(filepath.Separator)) >= 3 {
					return filepath.SkipDir
				}
				return nil
			}
			if fi, err := e.Info(); err == nil && browserFiles[e.Name()] && fi.Mode().Perm()&0o044 != 0 {
				sev, note := openSeverity(c.home, p)
				out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: sev, Title: "Browser password/cookie store readable by other users" + note,
					Evidence: "mode " + fi.Mode().Perm().String(), Location: finding.Location{Path: tilde(c.home, p)},
					Remediation: "chmod 600 the file and chmod 700 the profile directory."}))
			}
			return nil
		})
	}
	basic := regexp.MustCompile(`password-store=basic`)
	for _, f := range flagFiles {
		if b, err := os.ReadFile(filepath.Join(c.home, f)); err == nil && basic.Match(b) {
			out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: finding.Medium, Title: "Chromium saves passwords with the weak 'basic' store (no keyring)",
				Location: finding.Location{Path: "~/" + f}, Remediation: "Use --password-store=gnome-libsecret or kwallet instead of basic."}))
		}
	}
	return out, nil
}

// ---- HOST-008: debug ports ----

type debugPorts struct{ proc string }

func (debugPorts) ID() string       { return "HOST-008" }
func (debugPorts) Category() string { return "host" }
func (debugPorts) Title() string    { return "Debug/remote-control port enabled on a running process" }

var anyAddr = regexp.MustCompile(`(0\.0\.0\.0|::)`)

func (c debugPorts) Run(_ context.Context, _ check.Env) ([]finding.Finding, error) {
	var out []finding.Finding
	seen := map[string]bool{}
	for _, argv := range procCmdlines(c.proc) {
		name := filepath.Base(argv[0])
		for _, a := range argv[1:] {
			sev, title := finding.Severity(-1), ""
			switch {
			case strings.HasPrefix(a, "--remote-debugging-address=") && anyAddr.MatchString(a):
				sev, title = finding.Critical, "Browser remote debugging exposed on all interfaces"
			case strings.HasPrefix(a, "--remote-allow-origins=*"):
				sev, title = finding.High, "Browser remote debugging accepts any origin"
			case strings.HasPrefix(a, "--remote-debugging-port"):
				sev, title = finding.Medium, "Browser remote debugging port open (any local process can drive the browser)"
			case strings.HasPrefix(a, "--inspect") && anyAddr.MatchString(a):
				sev, title = finding.High, "Node inspector exposed on all interfaces (remote code execution)"
			case strings.HasPrefix(a, "--inspect"):
				sev, title = finding.Low, "Node inspector enabled (any local process can attach)"
			}
			if sev < 0 {
				continue
			}
			ev := name + " " + a // argv only for the flag, never the whole command line (may hold secrets)
			if seen[ev] {
				continue
			}
			seen[ev] = true
			out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: sev, Title: title, Evidence: ev,
				Location:    finding.Location{Path: "process:" + name},
				Remediation: "Drop the flag outside of active debugging; if needed bind to 127.0.0.1 only."}))
		}
	}
	return out, nil
}
