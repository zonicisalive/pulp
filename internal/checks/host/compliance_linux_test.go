//go:build linux

package host

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zonicisalive/pulp/internal/check"
)

const mi = `26 1 253:0 / / rw - ext4 /dev/mapper/vg-root rw
30 26 8:3 / /home rw - ext4 /dev/sda3 rw
31 26 0:25 / /tmp rw - tmpfs tmpfs rw
`

func lsblk(out string) runFn {
	return func(_ context.Context, name string, args ...string) string { return out }
}

func TestDiskEncryption(t *testing.T) {
	p := filepath.Join(t.TempDir(), "mountinfo")
	os.WriteFile(p, []byte(mi), 0o600)
	ctx := context.Background()
	if got, _ := (diskEncryption{p, lsblk("part\ndisk")}).Run(ctx, check.Env{}); len(got) != 1 {
		t.Error("plain disk must be flagged")
	}
	if got, _ := (diskEncryption{p, lsblk("crypt\npart\ndisk")}).Run(ctx, check.Env{}); len(got) != 0 {
		t.Error("crypt device must pass")
	}
	if got, _ := (diskEncryption{p, lsblk("")}).Run(ctx, check.Env{}); len(got) != 0 {
		t.Error("no lsblk answer must stay silent")
	}
	os.WriteFile(p, []byte("1 0 0:1 / / rw - overlay overlay rw\n"), 0o600)
	if got, _ := (diskEncryption{p, lsblk("part")}).Run(ctx, check.Env{}); len(got) != 0 {
		t.Error("container overlay root must stay silent")
	}
}

func TestScreenLock(t *testing.T) {
	ctx := context.Background()
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	gs := func(answers map[string]string) runFn {
		return func(_ context.Context, _ string, args ...string) string { return answers[args[len(args)-1]] }
	}
	headless := screenLock{gs(nil), env(nil), t.TempDir()}
	if got, _ := headless.Run(ctx, check.Env{}); len(got) != 0 {
		t.Error("no graphical session must stay silent")
	}
	gnome := map[string]string{"XDG_SESSION_TYPE": "wayland", "XDG_CURRENT_DESKTOP": "GNOME"}
	if got, _ := (screenLock{gs(map[string]string{"lock-enabled": "false"}), env(gnome), ""}).Run(ctx, check.Env{}); len(got) != 1 {
		t.Error("gnome lock disabled must be flagged")
	}
	if got, _ := (screenLock{gs(map[string]string{"lock-enabled": "true", "idle-delay": "uint32 300"}), env(gnome), ""}).Run(ctx, check.Env{}); len(got) != 0 {
		t.Error("healthy gnome must pass")
	}
	if got, _ := (screenLock{gs(map[string]string{"lock-enabled": "true", "idle-delay": "uint32 0"}), env(gnome), ""}).Run(ctx, check.Env{}); len(got) != 1 {
		t.Error("idle-delay 0 must be flagged")
	}
	// other desktops: look for a running idle locker
	proc := t.TempDir()
	os.MkdirAll(filepath.Join(proc, "9"), 0o700)
	hypr := map[string]string{"XDG_SESSION_TYPE": "wayland", "XDG_CURRENT_DESKTOP": "Hyprland"}
	if got, _ := (screenLock{gs(nil), env(hypr), proc}).Run(ctx, check.Env{}); len(got) != 1 {
		t.Error("no locker running must be flagged")
	}
	os.WriteFile(filepath.Join(proc, "9", "cmdline"), []byte("/usr/bin/hypridle\x00"), 0o600)
	if got, _ := (screenLock{gs(nil), env(hypr), proc}).Run(ctx, check.Env{}); len(got) != 0 {
		t.Error("hypridle running must pass")
	}
}

func TestSysUpdates(t *testing.T) {
	root := t.TempDir()
	w := func(rel, body string) {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(body), 0o644)
	}
	w("var/log/pacman.log", "[2026-01-01T10:00:00+0000] [PACMAN] starting full system upgrade\n[2026-06-01T10:00:00+0000] [PACMAN] starting full system upgrade\n")
	w("proc/sys/kernel/osrelease", "6.1.0-old\n")
	os.MkdirAll(filepath.Join(root, "usr/lib/modules/6.2.0-new"), 0o755)
	now := func() time.Time { return time.Date(2026, 6, 20, 0, 0, 0, 0, time.UTC) }
	got, _ := (sysUpdates{root, now}).Run(context.Background(), check.Env{})
	if len(got) != 1 || got[0].Severity.String() != "low" { // 19 days old: fine; kernel gone: low
		t.Fatalf("want only reboot-pending low, got %+v", got)
	}
	now = func() time.Time { return time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC) } // 80 days
	got, _ = (sysUpdates{root, now}).Run(context.Background(), check.Env{})
	if len(got) != 2 {
		t.Fatalf("want overdue + reboot, got %+v", got)
	}
}
