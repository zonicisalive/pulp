package report

import "github.com/zonicisalive/pulp/internal/finding"

// Summary counts findings per severity and derives a 0-100 hardening score.
type Summary struct {
	Counts [5]int // indexed by finding.Severity
	Score  int
}

var penalty = [5]int{0, 1, 4, 10, 25} // info, low, medium, high, critical

func Summarize(fnds []finding.Finding) Summary {
	var s Summary
	lost := 0
	for _, f := range fnds {
		s.Counts[f.Severity]++
		lost += penalty[f.Severity]
	}
	s.Score = max(0, 100-lost)
	return s
}
