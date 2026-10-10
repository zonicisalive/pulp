// Package check holds the Check interface and the concurrent runner.
package check

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zonicisalive/pulp/internal/finding"
)

type Options struct {
	Only, Skip []string // check IDs or categories
}

type Env struct {
	Root string
	Opts Options
}

type Check interface {
	ID() string       // e.g. "DOCK-001"
	Category() string // docker|git|cors|postgres
	Title() string
	Run(ctx context.Context, env Env) ([]finding.Finding, error)
}

var registry []Check

func Register(c Check) { registry = append(registry, c) }

func All() []Check { return registry }

func match(c Check, list []string) bool {
	for _, v := range list {
		if v == c.ID() || v == c.Category() {
			return true
		}
	}
	return false
}

// Run executes selected checks in parallel, 10s timeout each. A failing
// check yields an error entry; it never aborts the scan.
func Run(ctx context.Context, env Env) ([]finding.Finding, []error) {
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		out  []finding.Finding
		errs []error
	)
	for _, c := range registry {
		if len(env.Opts.Only) > 0 && !match(c, env.Opts.Only) || match(c, env.Opts.Skip) {
			continue
		}
		wg.Add(1)
		go func(c Check) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			fs, err := c.Run(cctx, env)
			mu.Lock()
			defer mu.Unlock()
			out = append(out, fs...)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", c.ID(), err))
			}
		}(c)
	}
	wg.Wait()
	return out, errs
}
