//go:build linux

// Package docker holds Docker misconfiguration checks.
package docker

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"strconv"
	"syscall"

	"github.com/zonicisalive/pulp/internal/check"
	"github.com/zonicisalive/pulp/internal/finding"
)

const socketPath = "/var/run/docker.sock"

// dock001 flags a Docker socket reachable by users outside root/docker.
type dock001 struct{ path string }

func init() { check.Register(dock001{socketPath}) }

func (dock001) ID() string       { return "DOCK-001" }
func (dock001) Category() string { return "docker" }
func (dock001) Title() string    { return "Docker socket permissions too open" }

func (c dock001) Run(_ context.Context, _ check.Env) ([]finding.Finding, error) {
	fi, err := os.Stat(c.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil // docker not installed: nothing to report
	}
	if err != nil {
		return nil, err
	}
	perm := fi.Mode().Perm()
	st, _ := fi.Sys().(*syscall.Stat_t)
	group := "?"
	if st != nil {
		group = strconv.Itoa(int(st.Gid))
		if g, err := user.LookupGroupId(group); err == nil {
			group = g.Name
		}
	}
	ev := fmt.Sprintf("%s mode %04o group %s", c.path, perm, group)
	loc := finding.Location{Path: c.path}
	fix := "chmod 660 " + c.path + " && chgrp docker " + c.path

	switch {
	case perm&0o002 != 0:
		return []finding.Finding{finding.New(finding.Input{ID: c.ID(), Title: "Docker socket is world-writable (root-equivalent for any local user)",
			Severity: finding.Critical, Location: loc, Evidence: ev, Remediation: fix})}, nil
	case perm&0o004 != 0:
		return []finding.Finding{finding.New(finding.Input{ID: c.ID(), Title: "Docker socket is world-readable",
			Severity: finding.High, Location: loc, Evidence: ev, Remediation: fix})}, nil
	case group != "docker" && group != "root":
		return []finding.Finding{finding.New(finding.Input{ID: c.ID(), Title: "Docker socket owned by unexpected group",
			Severity: finding.Medium, Location: loc, Evidence: ev, Remediation: fix})}, nil
	}
	return nil, nil
}
