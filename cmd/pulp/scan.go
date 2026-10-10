package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zonicisalive/pulp/internal/check"
	"github.com/zonicisalive/pulp/internal/finding"
	"github.com/zonicisalive/pulp/internal/ignore"
	"github.com/zonicisalive/pulp/internal/report"
)

func split(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// ignoreSet loads <root>/.pulp-ignore and the user-wide ~/.config/pulp/ignore.
func ignoreSet(root string) *ignore.Set {
	return ignore.Load(filepath.Join(root, ".pulp-ignore"), userIgnorePath())
}

func userIgnorePath() string {
	d, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "pulp", "ignore")
}

func runChecks(root string, only, skip string) ([]finding.Finding, []error) {
	fnds, errs := check.Run(context.Background(), check.Env{Root: root,
		Opts: check.Options{Only: split(only), Skip: split(skip)}})
	sort.Slice(fnds, func(i, j int) bool { return fnds[i].Severity > fnds[j].Severity })
	return fnds, errs
}

func scan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "JSON output (same as --format json)")
	asSARIF := fs.Bool("sarif", false, "SARIF 2.1.0 output (same as --format sarif)")
	format := fs.String("format", "table", "table | json | sarif | compliance")
	failOn := fs.String("fail-on", "high", "exit 1 at/above this severity")
	only := fs.String("only", "", "comma list of check IDs/categories")
	skip := fs.String("skip", "", "comma list of check IDs/categories to skip (e.g. host)")
	noIgnore := fs.Bool("no-ignore", false, "do not apply .pulp-ignore")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	threshold, err := finding.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	root := "."
	if fs.NArg() > 0 {
		root = fs.Arg(0)
	}
	fnds, errs := runChecks(root, *only, *skip)
	suppressed := 0
	if *noIgnore {
		if fnds == nil {
			fnds = []finding.Finding{}
		}
	} else {
		fnds, suppressed = ignoreSet(root).Filter(fnds)
	}

	if *asSARIF {
		*format = "sarif"
	} else if *asJSON {
		*format = "json"
	}
	switch *format {
	case "sarif":
		report.SARIF(os.Stdout, version, fnds)
	case "compliance":
		report.Compliance(os.Stdout, version, check.All(), fnds)
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(fnds)
	case "table":
		table(os.Stdout, fnds, suppressed, useColor())
	default:
		fmt.Fprintf(os.Stderr, "unknown --format %q\n", *format)
		return 2
	}
	for _, e := range errs {
		fmt.Fprintln(os.Stderr, "error:", e)
	}
	if len(errs) > 0 {
		return 2
	}
	for _, f := range fnds {
		if f.Severity >= threshold {
			return 1
		}
	}
	return 0
}

func useColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

var sevColor = [...]string{"\x1b[2m", "\x1b[36m", "\x1b[33m", "\x1b[31m", "\x1b[1;31m"}

func table(w io.Writer, fnds []finding.Finding, suppressed int, color bool) {
	paint := func(s finding.Severity, text string) string {
		if !color {
			return text
		}
		return sevColor[s] + text + "\x1b[0m"
	}
	for _, f := range fnds {
		fmt.Fprintf(w, "%s %s  %s\n           %s\n           fix: %s\n",
			paint(f.Severity, fmt.Sprintf("[%-8s]", f.Severity)), f.ID, f.Title, where(f), f.Remediation)
	}
	s := report.Summarize(fnds)
	parts := []string{}
	for sev := finding.Critical; sev >= finding.Info; sev-- {
		if n := s.Counts[sev]; n > 0 {
			parts = append(parts, paint(sev, fmt.Sprintf("%d %s", n, sev)))
		}
	}
	if len(parts) == 0 {
		parts = append(parts, "no findings")
	}
	if suppressed > 0 {
		parts = append(parts, fmt.Sprintf("%d ignored", suppressed))
	}
	if len(fnds) > 0 {
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "Score %d/100 · %s\n", s.Score, strings.Join(parts, " · "))
}

// where renders "path:line @commit  evidence" for the table view.
func where(f finding.Finding) string {
	s := f.Location.Path
	if f.Location.Line > 0 {
		s += fmt.Sprintf(":%d", f.Location.Line)
	}
	if f.Location.Commit != "" {
		s += " @" + f.Location.Commit
	}
	if f.Evidence != "" {
		s += "  " + f.Evidence
	}
	return s
}

// baseline records every current finding so only new ones are reported later.
// HOST-* findings go to the user-wide file, everything else to <root>/.pulp-ignore.
func baseline(args []string) int {
	root := "."
	if len(args) > 0 {
		root = args[0]
	}
	fnds, errs := runChecks(root, "", "")
	for _, e := range errs {
		fmt.Fprintln(os.Stderr, "error:", e)
	}
	var proj, user []finding.Finding
	for _, f := range fnds {
		if strings.HasPrefix(f.ID, "HOST-") {
			user = append(user, f)
		} else {
			proj = append(proj, f)
		}
	}
	n1, err1 := ignore.Append(filepath.Join(root, ".pulp-ignore"), proj)
	n2 := 0
	var err2 error
	if up := userIgnorePath(); len(user) > 0 && up != "" {
		os.MkdirAll(filepath.Dir(up), 0o700)
		n2, err2 = ignore.Append(up, user)
	}
	for _, e := range []error{err1, err2} {
		if e != nil {
			fmt.Fprintln(os.Stderr, "error:", e)
			return 2
		}
	}
	fmt.Printf("baseline: %d project finding(s) -> %s/.pulp-ignore, %d machine finding(s) -> %s\n", n1, root, n2, userIgnorePath())
	return 0
}
