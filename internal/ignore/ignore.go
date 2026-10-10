// Package ignore implements the .pulp-ignore suppression file.
//
// One rule per line, '#' starts a comment:
//
//	<64-hex fingerprint>         exact finding
//	GIT-001                      a whole check
//	GIT-001 docs/*               check + path (a trailing * is a prefix match)
//	GIT-001 commit:e0cc948       check + commit prefix
package ignore

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/zonicisalive/pulp/internal/finding"
)

type rule struct{ fp, id, glob, commit string }

type Set struct{ rules []rule }

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Load reads the given files; missing or unreadable files are skipped.
func Load(paths ...string) *Set {
	s := &Set{}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			l := sc.Text()
			if i := strings.IndexByte(l, '#'); i >= 0 {
				l = l[:i]
			}
			fs := strings.Fields(l)
			if len(fs) == 0 {
				continue
			}
			if hex64.MatchString(fs[0]) {
				s.rules = append(s.rules, rule{fp: fs[0]})
				continue
			}
			r := rule{id: fs[0]}
			for _, a := range fs[1:] {
				if c, ok := strings.CutPrefix(a, "commit:"); ok {
					r.commit = c
				} else {
					r.glob = a
				}
			}
			s.rules = append(s.rules, r)
		}
		f.Close()
	}
	return s
}

func globMatch(glob, path string) bool {
	if p, ok := strings.CutSuffix(glob, "*"); ok && !strings.ContainsAny(p, "*?[") {
		return strings.HasPrefix(path, p)
	}
	ok, _ := filepath.Match(glob, path)
	return ok || glob == path
}

func (s *Set) Match(f finding.Finding) bool {
	for _, r := range s.rules {
		switch {
		case r.fp != "":
			if r.fp == f.Fingerprint {
				return true
			}
		case r.id == f.ID &&
			(r.glob == "" || globMatch(r.glob, f.Location.Path)) &&
			(r.commit == "" || (f.Location.Commit != "" && strings.HasPrefix(f.Location.Commit, r.commit))):
			return true
		}
	}
	return false
}

// Filter drops ignored findings and reports how many were suppressed.
func (s *Set) Filter(in []finding.Finding) (kept []finding.Finding, suppressed int) {
	kept = []finding.Finding{}
	for _, f := range in {
		if s.Match(f) {
			suppressed++
		} else {
			kept = append(kept, f)
		}
	}
	return
}

// Append adds one fingerprint line per finding to path, skipping known ones.
// Comments hold only the check ID and location, never evidence.
func Append(path string, fnds []finding.Finding) (added int, err error) {
	known := Load(path)
	out, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	for _, f := range fnds {
		if known.Match(f) {
			continue
		}
		loc := f.Location.Path
		if f.Location.Line > 0 {
			loc += fmt.Sprintf(":%d", f.Location.Line)
		}
		if _, err := fmt.Fprintf(out, "%s # %s %s\n", f.Fingerprint, f.ID, loc); err != nil {
			return added, err
		}
		added++
	}
	return added, nil
}
