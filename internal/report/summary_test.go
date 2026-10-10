package report

import (
	"testing"

	"github.com/zonicisalive/pulp/internal/finding"
)

func TestScore(t *testing.T) {
	f := func(s finding.Severity) finding.Finding { return finding.Finding{Severity: s} }
	if got := Summarize(nil).Score; got != 100 {
		t.Errorf("clean = %d", got)
	}
	got := Summarize([]finding.Finding{f(finding.Critical), f(finding.High), f(finding.Medium), f(finding.Low)})
	if got.Score != 60 || got.Counts[finding.High] != 1 {
		t.Errorf("got %+v", got)
	}
	many := make([]finding.Finding, 10)
	for i := range many {
		many[i] = f(finding.Critical)
	}
	if Summarize(many).Score != 0 {
		t.Error("score must floor at 0")
	}
}
