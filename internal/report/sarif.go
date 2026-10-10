// Package report renders findings in machine formats.
package report

import (
	"encoding/json"
	"io"

	"github.com/zonicisalive/pulp/internal/check"
	"github.com/zonicisalive/pulp/internal/finding"
)

func level(s finding.Severity) string {
	switch {
	case s >= finding.High:
		return "error"
	case s == finding.Medium:
		return "warning"
	}
	return "note"
}

// SARIF writes a SARIF 2.1.0 log. Rules come from the registered checks.
func SARIF(w io.Writer, version string, fnds []finding.Finding) error {
	type m = map[string]any
	rules := []m{}
	for _, c := range check.All() {
		rules = append(rules, m{"id": c.ID(), "shortDescription": m{"text": c.Title()}})
	}
	results := []m{}
	for _, f := range fnds {
		loc := m{"artifactLocation": m{"uri": f.Location.Path}}
		if f.Location.Line > 0 {
			loc["region"] = m{"startLine": f.Location.Line}
		}
		results = append(results, m{
			"ruleId":              f.ID,
			"level":               level(f.Severity),
			"message":             m{"text": f.Title + ". " + f.Remediation},
			"locations":           []m{{"physicalLocation": loc}},
			"partialFingerprints": m{"github.com/zonicisalive/pulp/v1": f.Fingerprint},
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(m{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []m{{
			"tool":    m{"driver": m{"name": "pulp", "version": version, "rules": rules}},
			"results": results,
		}},
	})
}
