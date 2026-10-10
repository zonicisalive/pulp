// Package host audits the developer's home directory: SSH keys, credential files, shell history.
package host

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/zonicisalive/pulp/internal/check"
	"github.com/zonicisalive/pulp/internal/finding"
	"github.com/zonicisalive/pulp/internal/fsutil"
	"github.com/zonicisalive/pulp/internal/secrets"
)

func init() {
	home, err := os.UserHomeDir()
	if err != nil {
		return // no home: host checks are not registered
	}
	check.Register(sshKeys{home})
	check.Register(credFiles{home})
	check.Register(shellSecrets{home})
}

// tilde shows paths as ~/... so reports never carry the username.
func tilde(home, p string) string {
	if rel, err := filepath.Rel(home, p); err == nil {
		return "~/" + rel
	}
	return p
}

// exposed reports whether another local user could reach p: every directory from p's
// parent up to home must grant group or other traverse (x) permission.
func exposed(home, p string) bool {
	for d := filepath.Dir(p); ; d = filepath.Dir(d) {
		if fi, err := os.Stat(d); err != nil || fi.Mode().Perm()&0o011 == 0 {
			return false
		}
		if d == home || d == "/" || d == "." {
			return true
		}
	}
}

// openSeverity: High when the loose file is reachable by others, Low when a private
// parent directory still blocks them (defence in depth).
func openSeverity(home, p string) (finding.Severity, string) {
	if exposed(home, p) {
		return finding.High, ""
	}
	return finding.Low, " (parent directory currently blocks access)"
}

// ---- HOST-001: SSH keys ----

type sshKeys struct{ home string }

func (sshKeys) ID() string       { return "HOST-001" }
func (sshKeys) Category() string { return "host" }
func (sshKeys) Title() string    { return "SSH directory or private key too open / unencrypted" }

func (c sshKeys) Run(_ context.Context, _ check.Env) ([]finding.Finding, error) {
	dir := filepath.Join(c.home, ".ssh")
	di, err := os.Stat(dir)
	if err != nil || !di.IsDir() {
		return nil, nil
	}
	var out []finding.Finding
	add := func(sev finding.Severity, conf, title, path, fix string) {
		out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: sev, Confidence: conf, Title: title,
			Location: finding.Location{Path: tilde(c.home, path)}, Remediation: fix}))
	}
	if di.Mode().Perm()&0o022 != 0 {
		add(finding.High, "high", "~/.ssh is writable by group/others", dir, "chmod 700 ~/.ssh")
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		fi, err := os.Stat(p) // follows symlinks
		if err != nil || !fi.Mode().IsRegular() || fi.Size() > 64<<10 || strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil || !strings.Contains(string(b), "PRIVATE KEY-----") {
			continue
		}
		if fi.Mode().Perm()&0o077 != 0 {
			add(finding.High, "high", "SSH private key readable by group/others", p, "chmod 600 "+tilde(c.home, p))
		}
		if !encrypted(b) {
			add(finding.Medium, "medium", "SSH private key has no passphrase", p,
				"Add one with ssh-keygen -p -f "+tilde(c.home, p)+" (or keep keys on a hardware token / agent).")
		}
	}
	return out, nil
}

// encrypted reports whether a private key file is passphrase-protected.
func encrypted(b []byte) bool {
	s := string(b)
	if !strings.Contains(s, "BEGIN OPENSSH PRIVATE KEY") {
		return strings.Contains(s, "ENCRYPTED") // PEM / PKCS8
	}
	var body strings.Builder
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "-----") {
			body.WriteString(l)
		}
	}
	raw, err := base64.StdEncoding.DecodeString(body.String())
	const magic = "openssh-key-v1\x00"
	if err != nil || len(raw) < len(magic)+4 || string(raw[:len(magic)]) != magic {
		return true // cannot tell: do not raise a finding
	}
	n := int(binary.BigEndian.Uint32(raw[len(magic):]))
	if n < 0 || len(magic)+4+n > len(raw) {
		return true
	}
	return string(raw[len(magic)+4:len(magic)+4+n]) != "none"
}

// ---- HOST-002: credential files ----

type credFiles struct{ home string }

func (credFiles) ID() string       { return "HOST-002" }
func (credFiles) Category() string { return "host" }
func (credFiles) Title() string    { return "Credential file readable by others or stored in plaintext" }

var credList = []struct {
	rel    string
	marker *regexp.Regexp
}{
	{".aws/credentials", regexp.MustCompile(`aws_secret_access_key`)},
	{".kube/config", regexp.MustCompile(`(token|client-key-data|password):`)},
	{".docker/config.json", regexp.MustCompile(`"auth"\s*:\s*"`)},
	{".npmrc", regexp.MustCompile(`_authToken|_auth=|_password`)},
	{".pypirc", regexp.MustCompile(`password`)},
	{".netrc", regexp.MustCompile(`password`)},
	{".git-credentials", regexp.MustCompile(`://[^:/\s]+:[^@\s]+@`)},
	{".config/gh/hosts.yml", regexp.MustCompile(`oauth_token`)},
	{".config/gcloud/application_default_credentials.json", regexp.MustCompile(`refresh_token|private_key`)},
}

func (c credFiles) Run(_ context.Context, _ check.Env) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, cf := range credList {
		p := filepath.Join(c.home, cf.rel)
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() || fi.Size() > 1<<20 {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil || !cf.marker.Match(b) {
			continue
		}
		loc := finding.Location{Path: tilde(c.home, p)}
		switch {
		case fi.Mode().Perm()&0o077 != 0:
			sev, note := openSeverity(c.home, p)
			out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: sev, Title: "Credential file readable by group/others" + note,
				Evidence: "mode " + fi.Mode().Perm().String(), Location: loc, Remediation: "chmod 600 " + loc.Path}))
		case cf.rel == ".git-credentials":
			out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: finding.Medium, Title: "Git credentials stored in plaintext",
				Location: loc, Remediation: "Switch to a credential helper (libsecret / gh auth) and delete this file."}))
		}
	}
	return out, nil
}

// ---- HOST-003: secrets in shell history / rc files ----

type shellSecrets struct{ home string }

func (shellSecrets) ID() string       { return "HOST-003" }
func (shellSecrets) Category() string { return "host" }
func (shellSecrets) Title() string    { return "Secret in shell history or rc file" }

var shellFiles = []string{".bash_history", ".zsh_history", ".local/share/fish/fish_history",
	".bashrc", ".zshrc", ".zshenv", ".profile", ".bash_profile", ".config/fish/config.fish"}

const histTail = 5000 // only the most recent lines of a history file

// shell-specific patterns; group 1 is the secret
var shellRules = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bexport\s+\w*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD)\w*=["']?([^\s"'$(][^\s"']{7,})`),
	regexp.MustCompile(`(?i)--(?:password|passwd|token|api-key)[= ]["']?([^\s"'$(-][^\s"']{5,})`),
	regexp.MustCompile(`(?i)authorization:\s*bearer\s+([A-Za-z0-9._~+/=-]{20,})`),
	regexp.MustCompile(`\bcurl\b.*\s-u\s+[^\s:]+:([^\s"']{4,})`),
	regexp.MustCompile(`\bmysql\b.*\s-p([^\s"']{4,})`),
}

func (c shellSecrets) Run(_ context.Context, _ check.Env) ([]finding.Finding, error) {
	var out []finding.Finding
	seen := map[string]bool{}
	for _, rel := range shellFiles {
		p := filepath.Join(c.home, rel)
		lines, ok := fsutil.ReadLines(p)
		if !ok {
			continue
		}
		first := 0
		if strings.HasSuffix(rel, "history") && len(lines) > histTail {
			first = len(lines) - histTail
		}
		for i := first; i < len(lines); i++ {
			name, val, conf := "", "", ""
			if m, ok := secrets.Scan(lines[i]); ok {
				name, val, conf = m.Name, m.Value, m.Confidence
			} else {
				for _, re := range shellRules {
					if m := re.FindStringSubmatch(lines[i]); m != nil && !secrets.IsPlaceholder(m[1]) {
						name, val, conf = "Credential on command line / export", m[1], "medium"
						break
					}
				}
			}
			if name == "" || seen[val] {
				continue
			}
			seen[val] = true
			out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: finding.High, Confidence: conf,
				Title: name + " in " + rel, Evidence: val, Secret: true,
				Location:    finding.Location{Path: tilde(c.home, p), Line: i + 1},
				Remediation: "Rotate it, delete the line, and load secrets from a secret manager or env file outside the shell rc."}))
		}
	}
	return out, nil
}
