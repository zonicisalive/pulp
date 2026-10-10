//go:build linux

package docker

import (
	"context"
	"regexp"
	"strings"

	"github.com/zonicisalive/pulp/internal/check"
	"github.com/zonicisalive/pulp/internal/finding"
	"github.com/zonicisalive/pulp/internal/fsutil"
)

// dock003 flags compose files that mount the Docker socket or run privileged.
type dock003 struct{}

func init() { check.Register(dock003{}) }

func (dock003) ID() string       { return "DOCK-003" }
func (dock003) Category() string { return "docker" }
func (dock003) Title() string    { return "Compose service mounts docker.sock or runs privileged" }

var (
	sockMount  = regexp.MustCompile(`docker\.sock`)
	privileged = regexp.MustCompile(`^\s*privileged:\s*true\b`)
)

func (c dock003) Run(ctx context.Context, env check.Env) ([]finding.Finding, error) {
	var out []finding.Finding
	fsutil.Files(ctx, env.Root, fsutil.ComposeName.MatchString, func(rel string, lines []string) {
		for i, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			loc := finding.Location{Path: rel, Line: i + 1}
			switch {
			case sockMount.MatchString(line):
				out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: finding.High,
					Title: "Compose mounts docker.sock (container gets root on host)", Evidence: strings.TrimSpace(line),
					Location: loc, Remediation: "Remove the mount or use a docker-socket-proxy with limited API access."}))
			case privileged.MatchString(line):
				out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: finding.High,
					Title: "Compose service runs privileged", Evidence: strings.TrimSpace(line),
					Location: loc, Remediation: "Drop privileged: true; grant only the needed cap_add entries."}))
			}
		}
	})
	return out, nil
}
