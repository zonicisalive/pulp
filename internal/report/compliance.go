package report

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/zonicisalive/pulp/internal/check"
	"github.com/zonicisalive/pulp/internal/finding"
)

const (
	cc61 = "SOC 2 CC6.1 (logical access)"
	cc63 = "SOC 2 CC6.3 (least privilege)"
	cc66 = "SOC 2 CC6.6 (boundary protection)"
	cc71 = "SOC 2 CC7.1 (vulnerability management)"
	i59  = "ISO 27001 A.8.9 (configuration management)"
	i517 = "ISO 27001 A.5.17 (authentication information)"
	i82  = "ISO 27001 A.8.2 (privileged access)"
	i88  = "ISO 27001 A.8.8 (technical vulnerabilities)"
	i820 = "ISO 27001 A.8.20 (network security)"
	i824 = "ISO 27001 A.8.24 (use of cryptography)"
	i828 = "ISO 27001 A.8.28 (secure coding)"
	i77  = "ISO 27001 A.7.7 (clear screen)"
)

// Controls maps each check ID to the framework controls it gives evidence for.
// Indicative only: it helps collect evidence, it is not audit advice.
var Controls = map[string][]string{
	"DOCK-001": {cc61, i59}, "DOCK-002": {cc66, i59}, "DOCK-003": {cc63, i59},
	"GIT-001": {cc61, i517}, "GIT-002": {cc61, i517},
	"CORS-001": {cc66, i828},
	"PG-001":   {cc61, i59}, "PG-002": {cc66, i820}, "PG-003": {cc61, i517},
	"DEV-001": {cc66, i828}, "DEV-002": {cc66, i820}, "DEV-003": {cc61, i828}, "DEV-004": {cc66, i824},
	"HOST-001": {cc61, i517}, "HOST-002": {cc61, i517}, "HOST-003": {cc61, i517},
	"HOST-004": {cc66, i820}, "HOST-005": {cc66, i820}, "HOST-006": {cc63, i82},
	"HOST-007": {cc61, i517}, "HOST-008": {cc66, i59},
	"DB-001": {cc61, i820}, "DB-002": {cc61, i59}, "DB-003": {cc61, i59}, "DB-004": {cc66, i517}, "GIT-003": {cc61, i517},
	"HOST-012": {cc61, i59}, "HOST-013": {cc66, i59}, "HOST-014": {cc61, i59},
	"CI-001": {cc71, i828}, "DOCK-004": {cc66, i59}, "PKG-001": {cc71, i88},
	"HOST-009": {cc61, i824}, "HOST-010": {cc61, i77}, "HOST-011": {cc71, i88},
}

// Compliance writes a Markdown evidence report. PASS means "the check ran and found
// nothing"; a check that cannot inspect this machine (no systemd, container) also
// reports no findings.
func Compliance(w io.Writer, version string, checks []check.Check, fnds []finding.Finding) {
	host, _ := os.Hostname()
	s := Summarize(fnds)
	fmt.Fprintf(w, "# Pulp hardening report\n\n- Generated: %s\n- Machine: %s\n- pulp: %s\n- Score: **%d/100**\n\n",
		time.Now().UTC().Format("2006-01-02 15:04 UTC"), host, version, s.Score)

	byID := map[string][]finding.Finding{}
	for _, f := range fnds {
		byID[f.ID] = append(byID[f.ID], f)
	}
	fmt.Fprintln(w, "| Check | Controls | Status |\n|---|---|---|")
	cs := append([]check.Check(nil), checks...)
	sort.Slice(cs, func(i, j int) bool { return cs[i].ID() < cs[j].ID() })
	for _, c := range cs {
		status := "PASS"
		if fs := byID[c.ID()]; len(fs) > 0 {
			top := fs[0].Severity
			for _, f := range fs {
				top = max(top, f.Severity)
			}
			status = fmt.Sprintf("**FAIL** (%d, %s)", len(fs), top)
		}
		fmt.Fprintf(w, "| %s %s | %s | %s |\n", c.ID(), c.Title(), strings.Join(Controls[c.ID()], "; "), status)
	}
	if len(fnds) > 0 {
		fmt.Fprint(w, "\n## Findings\n\n")
		for _, f := range fnds {
			loc := f.Location.Path
			if f.Location.Line > 0 {
				loc += fmt.Sprintf(":%d", f.Location.Line)
			}
			fmt.Fprintf(w, "- **%s** `%s` %s (%s). Fix: %s\n", f.Severity, f.ID, f.Title, loc, f.Remediation)
		}
	}
	fmt.Fprint(w, "\n_Indicative mapping to SOC 2 / ISO 27001 controls to help gather evidence; not audit advice. "+
		"PASS means no findings; checks that cannot inspect this machine also report no findings._\n")
}
