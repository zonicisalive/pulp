// Package linepat is the shared engine for "regex per line in matching files" checks.
package linepat

import (
	"context"
	"regexp"
	"strings"

	"github.com/zonicisalive/pulp/internal/finding"
	"github.com/zonicisalive/pulp/internal/fsutil"
)

// Pat is one rule. Rules are tried in order and the first match on a line wins,
// so put the most severe variant first.
type Pat struct {
	Re         *regexp.Regexp
	Sev        finding.Severity
	Title, Fix string
	Confidence string         // default "medium": these are text heuristics
	Secret     bool           // redact the evidence
	Not        *regexp.Regexp // if it also matches the line, this rule does not apply
}

// Opts tunes a scan.
type Opts struct {
	Comment string         // line comment prefix to skip ("#", "//"); empty = none
	Path    *regexp.Regexp // if set, the relative path must match
	FileRe  *regexp.Regexp // if set, some line of the file must match before it is scanned
}

// IsTestPath reports whether rel looks like a test, fixture or example path.
func IsTestPath(rel string) bool { return testPath.MatchString(rel) }

var testPath = regexp.MustCompile(`(?i)(^|/)(tests?|__tests__|spec|mocks?|fixtures?|examples?|testdata)(/|$)|[._-](test|spec)\.|_test\.`)

// Scan runs pats over every line of every file whose base name satisfies match.
// Test, fixture and example paths are skipped to keep noise down.
func Scan(ctx context.Context, root, id string, match func(string) bool, pats []Pat, o Opts) []finding.Finding {
	var out []finding.Finding
	fsutil.Files(ctx, root, match, func(rel string, lines []string) {
		if testPath.MatchString(rel) || (o.Path != nil && !o.Path.MatchString(rel)) {
			return
		}
		if o.FileRe != nil {
			found := false
			for _, l := range lines {
				if o.FileRe.MatchString(l) {
					found = true
					break
				}
			}
			if !found {
				return
			}
		}
		for i, l := range lines {
			t := strings.TrimSpace(l)
			if len(l) > 500 || t == "" || (o.Comment != "" && strings.HasPrefix(t, o.Comment)) {
				continue
			}
			for _, p := range pats {
				if !p.Re.MatchString(l) || (p.Not != nil && p.Not.MatchString(l)) {
					continue
				}
				conf := p.Confidence
				if conf == "" {
					conf = "medium"
				}
				out = append(out, finding.New(finding.Input{ID: id, Severity: p.Sev, Confidence: conf, Title: p.Title,
					Evidence: t, Secret: p.Secret, Location: finding.Location{Path: rel, Line: i + 1}, Remediation: p.Fix}))
				break
			}
		}
	})
	return out
}

// Names returns a matcher for exact base names or suffixes ("*.py" style via HasSuffix).
func Names(exact []string, suffixes []string) func(string) bool {
	return func(n string) bool {
		for _, e := range exact {
			if n == e {
				return true
			}
		}
		for _, s := range suffixes {
			if strings.HasSuffix(n, s) {
				return true
			}
		}
		return false
	}
}
