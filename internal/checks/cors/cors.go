// Package cors flags permissive CORS configuration in common web frameworks.
package cors

import (
	"context"
	"regexp"
	"strings"

	"github.com/zonicisalive/pulp/internal/check"
	"github.com/zonicisalive/pulp/internal/finding"
	"github.com/zonicisalive/pulp/internal/fsutil"
)

type cors001 struct{}

func init() { check.Register(cors001{}) }

func (cors001) ID() string       { return "CORS-001" }
func (cors001) Category() string { return "cors" }
func (cors001) Title() string    { return "Overly permissive CORS policy" }

var (
	srcFile = regexp.MustCompile(`\.(js|jsx|ts|tsx|mjs|cjs|py)$`)
	// wildcard or reflected-origin policies, across Express/Next/Vite/Django/Flask/FastAPI
	permissive = regexp.MustCompile(`(?i)(origin['"]?\s*[:=]\s*(\[\s*)?['"]\*['"]` +
		`|origin['"]?\s*:\s*true\b` +
		`|\bcors\(\s*\)` +
		`|access-control-allow-origin['"]?\s*[:,=]\s*['"]\*['"]` +
		`|access-control-allow-origin.*(req|request)\.headers\.origin` +
		`|CORS_(ORIGIN_)?ALLOW_ALL(_ORIGINS)?\s*=\s*True` +
		`|allow_origins\s*=\s*\[\s*['"]\*['"]` +
		`|\bCORS\(\s*app\s*\)` +
		`|origins\s*=\s*['"]\*['"])`)
	credentials = regexp.MustCompile(`(?i)(credentials['"]?\s*[:=]\s*true|CORS_ALLOW_CREDENTIALS\s*=\s*True|allow_credentials\s*=\s*True|Access-Control-Allow-Credentials['"]?\s*[:,=]\s*['"]?true)`)
)

func (c cors001) Run(ctx context.Context, env check.Env) ([]finding.Finding, error) {
	var out []finding.Finding
	fsutil.Files(ctx, env.Root, srcFile.MatchString, func(rel string, lines []string) {
		creds := false
		for _, l := range lines {
			if credentials.MatchString(l) {
				creds = true
				break
			}
		}
		for i, l := range lines {
			if len(l) > 500 || strings.HasPrefix(strings.TrimSpace(l), "//") || strings.HasPrefix(strings.TrimSpace(l), "#") {
				continue
			}
			if !permissive.MatchString(l) {
				continue
			}
			sev, title := finding.Medium, "CORS allows any origin"
			if creds {
				sev, title = finding.High, "CORS allows any origin together with credentials"
			}
			out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: sev, Confidence: "medium", Title: title,
				Evidence: strings.TrimSpace(l), Location: finding.Location{Path: rel, Line: i + 1},
				Remediation: "Allow an explicit origin list; never combine wildcard/reflected origins with credentials."}))
		}
	})
	return out, nil
}
