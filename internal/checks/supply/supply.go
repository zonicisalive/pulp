// Package supply audits CI workflows, Dockerfiles and package-manager config for supply-chain risks.
package supply

import (
	"context"
	"encoding/json"
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
	check.Register(actions{})
	check.Register(dockerfile{})
	check.Register(pkgConfig{})
}

func re(s string) *regexp.Regexp { return regexp.MustCompile(s) }

// ---- CI-001: GitHub Actions ----

type actions struct{}

func (actions) ID() string       { return "CI-001" }
func (actions) Category() string { return "ci" }
func (actions) Title() string    { return "Risky GitHub Actions workflow" }

const expr = `\$\{\{\s*(github\.head_ref|github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.ref|head\.label)|comment\.body|review\.body|head_commit\.message|commits\S*\.message|\S*\.email|pages\S*\.page_name))\s*\}\}`

var (
	pinned     = re(`@[0-9a-f]{40}\b|uses:\s*docker://`)
	keyValue   = re(`^\s*(-\s*)?[A-Za-z_][\w.-]*:\s`)
	workflowRe = re(`(^|/)\.github/(workflows|actions)/`)
	workflow   = []linepat.Pat{
		{Re: re(`^\s*(-\s*)?(run|script)\s*:.*` + expr), Sev: finding.High,
			Title: "Untrusted PR/issue text is interpolated straight into a shell step (expression injection)",
			Fix:   "Pass it through env: and reference \"$VAR\" in the script."},
		{Re: re(expr), Not: keyValue, Sev: finding.High,
			Title: "Untrusted PR/issue text is interpolated into a run script (expression injection)",
			Fix:   "Pass it through env: and reference \"$VAR\" in the script."},
		{Re: re(`^\s*permissions\s*:\s*write-all\b`), Sev: finding.Medium,
			Title: "Workflow token has write-all permissions", Fix: "Declare the minimum, e.g. permissions: contents: read."},
		{Re: re(`\becho\b.*\$\{\{\s*secrets\.`), Sev: finding.Medium,
			Title: "A secret is echoed in a step (ends up in logs, often decodable)", Fix: "Never print secrets; pass them via env to the tool that needs them."},
		{Re: re(`\b(curl|wget)\b[^|#]*\|\s*(sudo\s+)?(ba|z)?sh\b`), Sev: finding.Medium,
			Title: "Pipes a download into a shell", Fix: "Download, verify a checksum, then run."},
		{Re: re(`uses:\s*(actions|github)/[^@\s]+@`), Not: pinned, Sev: finding.Low,
			Title: "GitHub-owned action pinned to a mutable tag/branch", Fix: "Pin to a full commit SHA (comment the tag)."},
		{Re: re(`uses:\s*[^./\s][^@\s]*@`), Not: pinned, Sev: finding.Medium,
			Title: "Third-party action pinned to a mutable tag/branch (can be re-pointed to malicious code)", Fix: "Pin to a full commit SHA (comment the tag)."},
	}
	pwnRequest = []linepat.Pat{{
		Re: re(`ref\s*:\s*\$\{\{\s*github\.(event\.pull_request\.head\.(sha|ref)|head_ref)`), Sev: finding.High, Confidence: "high",
		Title: "pull_request_target workflow checks out untrusted PR code with write token/secrets (\"pwn request\")",
		Fix:   "Use pull_request, or never run PR code in a pull_request_target job.",
	}}
)

func yml(n string) bool { return strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".yaml") }

func (c actions) Run(ctx context.Context, env check.Env) ([]finding.Finding, error) {
	out := linepat.Scan(ctx, env.Root, c.ID(), yml, workflow, linepat.Opts{Comment: "#", Path: workflowRe})
	out = append(out, linepat.Scan(ctx, env.Root, c.ID(), yml, pwnRequest,
		linepat.Opts{Comment: "#", Path: workflowRe, FileRe: re(`pull_request_target`)})...)
	return out, nil
}

// ---- DOCK-004: Dockerfile ----

type dockerfile struct{}

func (dockerfile) ID() string       { return "DOCK-004" }
func (dockerfile) Category() string { return "docker" }
func (dockerfile) Title() string    { return "Insecure Dockerfile practice" }

func isDockerfile(n string) bool {
	return n == "Dockerfile" || n == "Containerfile" || strings.HasPrefix(n, "Dockerfile.") || strings.HasSuffix(n, ".Dockerfile")
}

var dockerPats = []linepat.Pat{
	{Re: re(`(?i)^\s*(ENV|ARG)\s+\w*(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY)\w*(=|\s+)["']?[^\s$"'][^\s"']{3,}`), Sev: finding.High, Secret: true,
		Title: "Secret baked into the image via ENV/ARG (visible in docker history)", Fix: "Use BuildKit secrets (--mount=type=secret) or pass at runtime."},
	{Re: re(`\b(curl|wget)\b[^|#]*\|\s*(sudo\s+)?(ba|z)?sh\b`), Sev: finding.Medium,
		Title: "RUN pipes a download into a shell", Fix: "Download, verify a checksum, then run."},
	{Re: re(`(?i)^\s*ADD\s+https?://`), Sev: finding.Medium,
		Title: "ADD from a URL with no integrity check", Fix: "Use curl/wget plus a pinned checksum, or ADD --checksum."},
	{Re: re(`\bchmod\s+(-R\s+)?0?777\b`), Sev: finding.Low, Title: "chmod 777 in image", Fix: "Grant only the needed bits."},
	{Re: re(`(?i)^\s*EXPOSE\s+(\S+\s+)*22(/tcp)?\b`), Sev: finding.Low, Title: "SSH port exposed from a container", Fix: "Use docker exec / a debug sidecar instead of sshd."},
}

func (c dockerfile) Run(ctx context.Context, env check.Env) ([]finding.Finding, error) {
	out := linepat.Scan(ctx, env.Root, c.ID(), isDockerfile, dockerPats, linepat.Opts{Comment: "#"})
	fsutil.Files(ctx, env.Root, isDockerfile, func(rel string, lines []string) {
		if linepat.IsTestPath(rel) {
			return
		}
		add := func(line int, sev finding.Severity, title, ev, fix string) {
			out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: sev, Confidence: "medium", Title: title, Evidence: ev,
				Location: finding.Location{Path: rel, Line: line}, Remediation: fix}))
		}
		aliases := map[string]bool{}
		lastFrom, user := 0, ""
		for i, l := range lines {
			f := strings.Fields(l)
			if len(f) < 2 || strings.HasPrefix(f[0], "#") {
				continue
			}
			switch strings.ToUpper(f[0]) {
			case "FROM":
				if strings.HasPrefix(f[1], "--") && len(f) > 2 {
					f = append(f[:1], f[2:]...)
				}
				lastFrom, user = i+1, ""
				img := f[1]
				if len(f) >= 4 && strings.EqualFold(f[2], "as") {
					aliases[f[3]] = true // later FROM lines may refer to this stage
				}
				if img == "scratch" || aliases[img] || strings.Contains(img, "$") || strings.Contains(img, "@sha256:") {
					continue
				}
				name := img[strings.LastIndex(img, "/")+1:]
				if !strings.Contains(name, ":") {
					add(i+1, finding.Medium, "Base image has no tag (floats to :latest)", img, "Pin a version tag, ideally a digest (@sha256:...).")
				} else if strings.HasSuffix(name, ":latest") {
					add(i+1, finding.Medium, "Base image uses :latest", img, "Pin a version tag, ideally a digest (@sha256:...).")
				}
			case "USER":
				user = f[1]
			}
		}
		if lastFrom > 0 && (user == "" || user == "root" || user == "0" || strings.HasPrefix(user, "root:") || strings.HasPrefix(user, "0:")) {
			add(lastFrom, finding.Medium, "Final image runs as root (no USER instruction)", "", "Add a non-root USER before the final CMD/ENTRYPOINT.")
		}
	})
	return out, nil
}

// ---- PKG-001: package manager config ----

type pkgConfig struct{}

func (pkgConfig) ID() string       { return "PKG-001" }
func (pkgConfig) Category() string { return "pkg" }
func (pkgConfig) Title() string    { return "Package manager config weakens supply-chain security" }

var pkgPats = []linepat.Pat{
	{Re: re(`_authToken\s*=\s*[A-Za-z0-9_.\-]{16,}`), Sev: finding.High, Confidence: "high", Secret: true,
		Title: "Literal registry token in project .npmrc", Fix: "Use _authToken=${NPM_TOKEN} and rotate the committed token."},
	{Re: re(`(?i)registry\s*=\s*http://`), Sev: finding.High, Confidence: "high", Title: "Package registry over plain HTTP", Fix: "Use https."},
	{Re: re(`(?i)strict-ssl\s*=\s*false`), Sev: finding.Medium, Title: "npm strict-ssl disabled", Fix: "Remove it; trust your CA via cafile."},
	{Re: re(`(?i)(--index-url|--extra-index-url|-i)\s+http://`), Sev: finding.High, Title: "pip index over plain HTTP", Fix: "Use an https index."},
	{Re: re(`--trusted-host\b`), Sev: finding.Medium, Title: "pip --trusted-host skips TLS verification for that host", Fix: "Fix the host's certificate instead."},
}

func pkgFile(n string) bool {
	return n == ".npmrc" || n == "pip.conf" || (strings.HasPrefix(n, "requirements") && strings.HasSuffix(n, ".txt"))
}

var lockfiles = []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock", "npm-shrinkwrap.json"}
var installScript = re(`(?i)\b(curl|wget)\b|\|\s*(ba)?sh\b|\beval\b|base64|node\s+-e|powershell|https?://`)

func hasLockfile(root, dir string) bool {
	for d := filepath.Join(root, dir); ; d = filepath.Dir(d) {
		for _, l := range lockfiles {
			if _, err := os.Stat(filepath.Join(d, l)); err == nil {
				return true
			}
		}
		if d == root || d == filepath.Dir(d) {
			return false
		}
	}
}

func (c pkgConfig) Run(ctx context.Context, env check.Env) ([]finding.Finding, error) {
	out := linepat.Scan(ctx, env.Root, c.ID(), pkgFile, pkgPats, linepat.Opts{Comment: "#"})
	fsutil.Files(ctx, env.Root, func(n string) bool { return n == "package.json" }, func(rel string, lines []string) {
		if linepat.IsTestPath(rel) {
			return
		}
		var pj struct {
			Scripts map[string]string `json:"scripts"`
			Deps    map[string]string `json:"dependencies"`
			Dev     map[string]string `json:"devDependencies"`
			Opt     map[string]string `json:"optionalDependencies"`
		}
		if json.Unmarshal([]byte(strings.Join(lines, "\n")), &pj) != nil {
			return
		}
		add := func(sev finding.Severity, title, ev, fix string) {
			out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: sev, Confidence: "medium", Title: title, Evidence: ev,
				Location: finding.Location{Path: rel}, Remediation: fix}))
		}
		for _, k := range []string{"preinstall", "install", "postinstall"} {
			if v := pj.Scripts[k]; v != "" && installScript.MatchString(v) {
				add(finding.High, k+" script downloads or evaluates code (runs on every install)", k+": "+v, "Move the logic into a reviewed build step; avoid network/eval in install hooks.")
			}
		}
		n := 0
		for _, deps := range []map[string]string{pj.Deps, pj.Dev, pj.Opt} {
			for name, v := range deps {
				n++
				switch {
				case strings.HasPrefix(v, "http://"):
					add(finding.High, "Dependency fetched over plain HTTP", name+": "+v, "Use a registry version or an https URL with integrity.")
				case strings.HasPrefix(v, "git://"):
					add(finding.Medium, "Dependency fetched over unauthenticated git://", name+": "+v, "Use git+https with a pinned commit.")
				case v == "*" || v == "latest" || v == "":
					add(finding.Low, "Dependency has no version bound", name+": "+v, "Pin or range-bound the version and commit a lockfile.")
				}
			}
		}
		if n > 0 && !hasLockfile(env.Root, filepath.Dir(rel)) {
			add(finding.Low, "package.json has dependencies but no lockfile", rel, "Commit package-lock.json / yarn.lock / pnpm-lock.yaml for reproducible, tamper-evident installs.")
		}
	})
	return out, nil
}
