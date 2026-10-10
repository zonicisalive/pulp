//go:build linux

package host

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/zonicisalive/pulp/internal/check"
	"github.com/zonicisalive/pulp/internal/finding"
	"github.com/zonicisalive/pulp/internal/fsutil"
	"github.com/zonicisalive/pulp/internal/procnet"
)

func init() {
	check.Register(sshdConfig{[]string{"/etc/ssh/sshd_config.d/*.conf", "/etc/ssh/sshd_config"}, procnet.Default})
	if home, err := os.UserHomeDir(); err == nil {
		check.Register(sshClient{home})
		check.Register(gitConfig{home})
	}
}

func fnd(id string, sev finding.Severity, conf, title, path string, line int, ev, fix string) finding.Finding {
	return finding.New(finding.Input{ID: id, Severity: sev, Confidence: conf, Title: title, Evidence: ev,
		Location: finding.Location{Path: path, Line: line}, Remediation: fix})
}

// ---- HOST-012: ~/.ssh/config ----

type sshClient struct{ home string }

func (sshClient) ID() string       { return "HOST-012" }
func (sshClient) Category() string { return "host" }
func (sshClient) Title() string    { return "Insecure SSH client option" }

func (c sshClient) Run(_ context.Context, _ check.Env) ([]finding.Finding, error) {
	path := filepath.Join(c.home, ".ssh", "config")
	lines, ok := fsutil.ReadLines(path)
	if !ok {
		return nil, nil
	}
	var out []finding.Finding
	host := "*" // options before any Host line apply to every host
	for i, raw := range lines {
		f := strings.Fields(strings.ReplaceAll(raw, "=", " "))
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		key, val := strings.ToLower(f[0]), strings.ToLower(f[1])
		global := host == "*"
		sev := func(g, s finding.Severity) finding.Severity {
			if global {
				return g
			}
			return s
		}
		loc, ev := "~/.ssh/config", strings.TrimSpace(raw)
		switch {
		case key == "host":
			host = f[1]
		case key == "stricthostkeychecking" && (val == "no" || val == "off"):
			out = append(out, fnd(c.ID(), sev(finding.Medium, finding.Low), "high", "StrictHostKeyChecking disabled: man-in-the-middle goes unnoticed", loc, i+1, ev,
				"Use accept-new, or pin the host key in known_hosts."))
		case key == "forwardagent" && val == "yes":
			out = append(out, fnd(c.ID(), sev(finding.Medium, finding.Info), "high", "ForwardAgent yes lets a compromised remote host use your keys", loc, i+1, ev,
				"Use ProxyJump instead, and enable ForwardAgent only for hosts you fully trust."))
		case key == "userknownhostsfile" && val == "/dev/null":
			out = append(out, fnd(c.ID(), sev(finding.Medium, finding.Low), "high", "known_hosts is discarded: host identity is never verified", loc, i+1, ev,
				"Keep the default known_hosts file."))
		}
	}
	return out, nil
}

// ---- HOST-013: sshd_config ----

type sshdConfig struct {
	globs   []string
	procNet []string
}

func (sshdConfig) ID() string       { return "HOST-013" }
func (sshdConfig) Category() string { return "host" }
func (sshdConfig) Title() string    { return "Insecure sshd setting on a machine running sshd" }

func (c sshdConfig) Run(_ context.Context, _ check.Env) ([]finding.Finding, error) {
	// first occurrence of a keyword wins in sshd, and drop-ins are read before the main file
	type kv struct {
		val, path string
		line      int
	}
	eff := map[string]kv{}
	var ports []uint64
	for _, g := range c.globs {
		paths, _ := filepath.Glob(g)
		sort.Strings(paths)
		for _, p := range paths {
			lines, ok := fsutil.ReadLines(p)
			if !ok {
				continue
			}
			for i, l := range lines {
				f := strings.Fields(strings.ReplaceAll(l, "=", " "))
				if len(f) < 2 || strings.HasPrefix(f[0], "#") {
					continue
				}
				k := strings.ToLower(f[0])
				if k == "port" {
					if n, err := strconv.ParseUint(f[1], 10, 16); err == nil {
						ports = append(ports, n)
					}
					continue
				}
				if _, seen := eff[k]; !seen {
					eff[k] = kv{strings.ToLower(f[1]), p, i + 1}
				}
			}
		}
	}
	if len(eff) == 0 && len(ports) == 0 {
		return nil, nil // sshd not installed / config unreadable
	}
	if len(ports) == 0 {
		ports = []uint64{22}
	}
	running := false
	for _, p := range ports {
		running = running || procnet.Listening(c.procNet, p)
	}
	if !running {
		return nil, nil // misconfigured but not reachable
	}
	var out []finding.Finding
	main := "/etc/ssh/sshd_config"
	flag := func(key string, sev finding.Severity, bad func(string) bool, deflt, title, fix string) {
		e, ok := eff[key]
		if !ok {
			e = kv{deflt, main, 0}
		}
		if bad(e.val) {
			ev := key + " " + e.val
			if !ok {
				ev += " (default)"
			}
			out = append(out, fnd(c.ID(), sev, "high", title, e.path, e.line, ev, fix))
		}
	}
	is := func(v string) func(string) bool { return func(x string) bool { return x == v } }
	flag("permitrootlogin", finding.High, is("yes"), "prohibit-password", "sshd allows root login with a password", "PermitRootLogin prohibit-password (or no)")
	flag("permitemptypasswords", finding.Critical, is("yes"), "no", "sshd accepts empty passwords", "PermitEmptyPasswords no")
	flag("passwordauthentication", finding.Medium, is("yes"), "yes", "sshd accepts password logins (brute-forceable)", "PasswordAuthentication no; use keys")
	flag("x11forwarding", finding.Low, is("yes"), "no", "sshd forwards X11 (clients can attack the X server)", "X11Forwarding no")
	flag("maxauthtries", finding.Low, func(v string) bool { n, _ := strconv.Atoi(v); return n > 6 }, "6", "sshd allows many auth attempts per connection", "MaxAuthTries 3")
	return out, nil
}

// ---- HOST-014: ~/.gitconfig ----

type gitConfig struct{ home string }

func (gitConfig) ID() string       { return "HOST-014" }
func (gitConfig) Category() string { return "host" }
func (gitConfig) Title() string    { return "Insecure global git setting" }

var (
	gitSection = regexp.MustCompile(`^\[\s*([A-Za-z0-9.-]+)(?:\s+"[^"]*")?\s*\]`)
	gitKey     = regexp.MustCompile(`^\s*([A-Za-z][\w-]*)\s*=\s*(.*?)\s*$`)
)

func (c gitConfig) Run(_ context.Context, _ check.Env) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, rel := range []string{".gitconfig", ".config/git/config"} {
		lines, ok := fsutil.ReadLines(filepath.Join(c.home, rel))
		if !ok {
			continue
		}
		section := ""
		for i, l := range lines {
			if m := gitSection.FindStringSubmatch(l); m != nil {
				section = strings.ToLower(m[1])
				continue
			}
			m := gitKey.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			name, val := section+"."+strings.ToLower(m[1]), strings.Trim(strings.ToLower(m[2]), `"`)
			loc, ev := "~/"+rel, strings.TrimSpace(l)
			switch {
			case name == "credential.helper" && strings.HasPrefix(val, "store"):
				out = append(out, fnd(c.ID(), finding.Medium, "high", "credential.helper=store keeps git passwords in plaintext", loc, i+1, ev,
					"Use libsecret / manager / cache, or gh auth setup-git."))
			case name == "http.sslverify" && (val == "false" || val == "no" || val == "0"):
				out = append(out, fnd(c.ID(), finding.High, "high", "http.sslVerify=false disables TLS verification for git over HTTPS", loc, i+1, ev,
					"Remove it; trust your CA with http.sslCAInfo."))
			case name == "safe.directory" && val == "*":
				out = append(out, fnd(c.ID(), finding.Medium, "high", "safe.directory=* disables git's repository-ownership protection", loc, i+1, ev,
					"List specific directories instead."))
			case name == "core.sshcommand" && strings.Contains(val, "stricthostkeychecking=no"):
				out = append(out, fnd(c.ID(), finding.Medium, "high", "core.sshCommand disables host key checking", loc, i+1, ev,
					"Remove StrictHostKeyChecking=no."))
			}
		}
	}
	return out, nil
}
