//go:build linux

package host

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zonicisalive/pulp/internal/check"
	"github.com/zonicisalive/pulp/internal/finding"
)

// runFn runs a command and returns its trimmed stdout ("" if it is missing or fails).
type runFn func(ctx context.Context, name string, args ...string) string

func runCmd(ctx context.Context, name string, args ...string) string {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func init() {
	check.Register(diskEncryption{"/proc/self/mountinfo", runCmd})
	check.Register(screenLock{runCmd, os.Getenv, "/proc"})
	check.Register(sysUpdates{"/", time.Now})
}

// ---- HOST-009: disk encryption ----

type diskEncryption struct {
	mountinfo string
	run       runFn
}

func (diskEncryption) ID() string       { return "HOST-009" }
func (diskEncryption) Category() string { return "host" }
func (diskEncryption) Title() string    { return "Disk is not encrypted (LUKS/dm-crypt)" }

// mountSources returns the /dev source of the last mount at each mountpoint.
func mountSources(mountinfo string, mountpoints ...string) []string {
	src := map[string]string{}
	for _, l := range strings.Split(mountinfo, "\n") {
		left, right, ok := strings.Cut(l, " - ")
		if !ok {
			continue
		}
		lf, rf := strings.Fields(left), strings.Fields(right)
		if len(lf) > 4 && len(rf) > 1 && strings.HasPrefix(rf[1], "/dev/") {
			src[lf[4]] = rf[1]
		}
	}
	var out []string
	for _, mp := range mountpoints {
		if s := src[mp]; s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (c diskEncryption) Run(ctx context.Context, _ check.Env) ([]finding.Finding, error) {
	b, err := os.ReadFile(c.mountinfo)
	if err != nil {
		return nil, nil
	}
	known := false
	for _, dev := range mountSources(string(b), "/", "/home") {
		out := c.run(ctx, "lsblk", "-s", "-rno", "TYPE", dev) // device and all its parents
		if out == "" {
			continue // lsblk missing or no answer
		}
		known = true
		for _, t := range strings.Fields(out) {
			if t == "crypt" {
				return nil, nil
			}
		}
	}
	if !known { // container, zfs, no lsblk: do not guess
		return nil, nil
	}
	return []finding.Finding{finding.New(finding.Input{ID: c.ID(), Severity: finding.Medium, Confidence: "medium",
		Title: "Neither / nor /home sits on an encrypted (dm-crypt) device", Location: finding.Location{Path: "/"},
		Remediation: "Enable LUKS full-disk encryption (at install time), or move /home to an encrypted volume."})}, nil
}

// ---- HOST-010: screen lock ----

type screenLock struct {
	run    runFn
	getenv func(string) string
	proc   string
}

func (screenLock) ID() string       { return "HOST-010" }
func (screenLock) Category() string { return "host" }
func (screenLock) Title() string    { return "No automatic screen lock" }

var idleLockers = map[string]bool{"swayidle": true, "hypridle": true, "xss-lock": true, "xautolock": true,
	"light-locker": true, "xidlehook": true, "gnome-screensaver": true, "xfce4-screensaver": true, "cinnamon-screensaver": true}

func (c screenLock) Run(ctx context.Context, _ check.Env) ([]finding.Finding, error) {
	if t := c.getenv("XDG_SESSION_TYPE"); t != "x11" && t != "wayland" && c.getenv("WAYLAND_DISPLAY") == "" && c.getenv("DISPLAY") == "" {
		return nil, nil // no graphical session (ssh, CI, container)
	}
	add := func(sev finding.Severity, conf, title, fix string) []finding.Finding {
		return []finding.Finding{finding.New(finding.Input{ID: c.ID(), Severity: sev, Confidence: conf, Title: title,
			Location: finding.Location{Path: "desktop session"}, Remediation: fix})}
	}
	desktop := strings.ToLower(c.getenv("XDG_CURRENT_DESKTOP"))
	switch {
	case strings.Contains(desktop, "gnome"):
		if c.run(ctx, "gsettings", "get", "org.gnome.desktop.screensaver", "lock-enabled") == "false" {
			return add(finding.Medium, "high", "GNOME screen lock is disabled", "gsettings set org.gnome.desktop.screensaver lock-enabled true"), nil
		}
		idle := strings.TrimPrefix(c.run(ctx, "gsettings", "get", "org.gnome.desktop.session", "idle-delay"), "uint32 ")
		if n, err := strconv.Atoi(idle); err == nil {
			if n == 0 {
				return add(finding.Medium, "high", "Screen never blanks or locks when idle", "gsettings set org.gnome.desktop.session idle-delay 300"), nil
			}
			if n > 900 {
				return add(finding.Low, "high", fmt.Sprintf("Idle lock delay is %d minutes (>15)", n/60), "gsettings set org.gnome.desktop.session idle-delay 300"), nil
			}
		}
		return nil, nil
	case strings.Contains(desktop, "kde"):
		for _, tool := range []string{"kreadconfig6", "kreadconfig5"} {
			if v := c.run(ctx, tool, "--file", "kscreenlockerrc", "--group", "Daemon", "--key", "Autolock"); v != "" {
				if v == "false" {
					return add(finding.Medium, "high", "KDE automatic screen lock is disabled", "System Settings > Screen Locking > Lock screen automatically"), nil
				}
				return nil, nil
			}
		}
		return nil, nil
	}
	for _, argv := range procCmdlines(c.proc) {
		if idleLockers[filepath.Base(argv[0])] {
			return nil, nil
		}
	}
	return add(finding.Low, "low", "No idle screen locker running (looked for swayidle, hypridle, xss-lock, xautolock, light-locker)",
		"Run an idle locker, e.g. hypridle/swayidle with hyprlock/swaylock, or xss-lock with i3lock."), nil
}

// ---- HOST-011: updates ----

type sysUpdates struct {
	root string // "/" in production; a temp dir in tests
	now  func() time.Time
}

func (sysUpdates) ID() string       { return "HOST-011" }
func (sysUpdates) Category() string { return "host" }
func (sysUpdates) Title() string    { return "System updates overdue or reboot pending" }

// lastUpdate returns the time of the newest package-manager upgrade found.
func (c sysUpdates) lastUpdate() (t time.Time, src string) {
	pm := filepath.Join(c.root, "var/log/pacman.log")
	if f, err := os.Open(pm); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			l := sc.Text()
			if len(l) > 26 && strings.Contains(l, "starting full system upgrade") {
				if ts, err := time.Parse("2006-01-02T15:04:05-0700", l[1:25]); err == nil {
					t, src = ts, "/var/log/pacman.log"
				}
			}
		}
		f.Close()
	}
	for _, rel := range []string{"var/log/apt/history.log", "var/log/dnf.rpm.log"} {
		if fi, err := os.Stat(filepath.Join(c.root, rel)); err == nil && fi.ModTime().After(t) {
			t, src = fi.ModTime(), "/"+rel
		}
	}
	return
}

func (c sysUpdates) Run(_ context.Context, _ check.Env) ([]finding.Finding, error) {
	var out []finding.Finding
	add := func(sev finding.Severity, title, path, fix string) {
		out = append(out, finding.New(finding.Input{ID: c.ID(), Severity: sev, Confidence: "medium", Title: title,
			Location: finding.Location{Path: path}, Remediation: fix}))
	}
	if last, src := c.lastUpdate(); !last.IsZero() {
		days := int(c.now().Sub(last).Hours() / 24)
		switch {
		case days > 90:
			add(finding.High, fmt.Sprintf("System not upgraded for %d days", days), src, "Run a full system upgrade now and reboot.")
		case days > 30:
			add(finding.Medium, fmt.Sprintf("System not upgraded for %d days", days), src, "Run a full system upgrade (security fixes ship continuously).")
		}
	}
	if rel, err := os.ReadFile(filepath.Join(c.root, "proc/sys/kernel/osrelease")); err == nil {
		mods := filepath.Join(c.root, "usr/lib/modules")
		if _, err := os.Stat(mods); err == nil {
			if _, err := os.Stat(filepath.Join(mods, strings.TrimSpace(string(rel)))); err != nil {
				add(finding.Low, "Running kernel "+strings.TrimSpace(string(rel))+" was replaced on disk; reboot to use the updated kernel",
					"/usr/lib/modules", "Reboot.")
			}
		}
	}
	if _, err := os.Stat(filepath.Join(c.root, "etc/apt")); err == nil { // Debian/Ubuntu family
		b, _ := os.ReadFile(filepath.Join(c.root, "etc/apt/apt.conf.d/20auto-upgrades"))
		if !strings.Contains(string(b), `Unattended-Upgrade "1"`) {
			add(finding.Low, "Unattended security upgrades are not enabled", "/etc/apt/apt.conf.d/20auto-upgrades",
				"sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades")
		}
	}
	return out, nil
}
