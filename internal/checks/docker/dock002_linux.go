//go:build linux

package docker

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"strings"

	"github.com/zonicisalive/pulp/internal/check"
	"github.com/zonicisalive/pulp/internal/finding"
	"github.com/zonicisalive/pulp/internal/procnet"
)

// dock002 flags dockerd exposed over plain TCP (2375 is the unauthenticated port).
type dock002 struct {
	daemonJSON string
	procNet    []string
}

func init() {
	check.Register(dock002{"/etc/docker/daemon.json", procnet.Default})
}

func (dock002) ID() string       { return "DOCK-002" }
func (dock002) Category() string { return "docker" }
func (dock002) Title() string    { return "Docker daemon exposed on unauthenticated TCP" }

const fix002 = "Remove the tcp:// host from dockerd config, or enable TLS client auth (port 2376)."

func (c dock002) Run(_ context.Context, _ check.Env) ([]finding.Finding, error) {
	var out []finding.Finding
	if b, err := os.ReadFile(c.daemonJSON); err == nil {
		var cfg struct {
			Hosts []string `json:"hosts"`
			TLS   bool     `json:"tls"`
		}
		if json.Unmarshal(b, &cfg) == nil && !cfg.TLS {
			for _, h := range cfg.Hosts {
				if strings.HasPrefix(h, "tcp://") {
					out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: finding.Critical,
						Title: "dockerd configured with tcp:// host and no TLS", Evidence: h,
						Location: finding.Location{Path: c.daemonJSON}, Remediation: fix002}))
				}
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if procnet.Listening(c.procNet, 2375) {
		out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: finding.Critical,
			Title:    "Something is listening on TCP 2375 (Docker plaintext API port)",
			Evidence: "port 2375 LISTEN", Location: finding.Location{Path: "/proc/net/tcp"}, Remediation: fix002}))
	}
	return out, nil
}
