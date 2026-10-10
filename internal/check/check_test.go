package check

import (
	"context"
	"testing"

	"github.com/zonicisalive/pulp/internal/finding"
)

type fake struct{ id, cat string }

func (f fake) ID() string       { return f.id }
func (f fake) Category() string { return f.cat }
func (f fake) Title() string    { return f.id }
func (f fake) Run(context.Context, Env) ([]finding.Finding, error) {
	return []finding.Finding{{ID: f.id}}, nil
}

func TestSelection(t *testing.T) {
	registry = []Check{fake{"A-1", "docker"}, fake{"HOST-1", "host"}}
	n := func(o Options) int { got, _ := Run(context.Background(), Env{Opts: o}); return len(got) }
	if got := n(Options{}); got != 2 {
		t.Errorf("default runs everything incl. host, ran %d", got)
	}
	if got := n(Options{Skip: []string{"host"}}); got != 1 {
		t.Errorf("--skip host must drop host checks, ran %d", got)
	}
	if got := n(Options{Only: []string{"HOST-1"}}); got != 1 {
		t.Errorf("--only by ID, ran %d", got)
	}
}
