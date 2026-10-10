//go:build linux

package host

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/zonicisalive/pulp/internal/check"
)

func fw(active, known bool) firewallFn {
	return func(context.Context) (bool, bool) { return active, known }
}

func TestFirewall(t *testing.T) {
	ctx := context.Background()
	if got, _ := (noFirewall{fw(false, true)}).Run(ctx, check.Env{}); len(got) != 1 {
		t.Error("inactive firewall must be flagged")
	}
	if got, _ := (noFirewall{fw(true, true)}).Run(ctx, check.Env{}); len(got) != 0 {
		t.Error("active firewall is clean")
	}
	if got, _ := (noFirewall{fw(false, false)}).Run(ctx, check.Env{}); len(got) != 0 {
		t.Error("unknown (no systemd) must stay silent")
	}
}

func TestOpenPorts(t *testing.T) {
	d := t.TempDir()
	tcp := filepath.Join(d, "tcp")
	os.WriteFile(tcp, []byte("  sl  local_address rem_address st\n"+
		"0: 00000000:18EB 00000000:0000 0A\n"+ // 6379 all interfaces -> flag
		"1: 0100007F:1538 00000000:0000 0A\n"+ // 5432 loopback only -> ignore
		"2: 00000000:0050 00000000:0000 0A\n"), 0o600) // 80 not risky
	got, _ := (openPorts{[]string{tcp}, fw(false, true)}).Run(context.Background(), check.Env{})
	if len(got) != 1 || got[0].Severity.String() != "high" {
		t.Fatalf("want 1 high finding for redis, got %+v", got)
	}
}

func TestSudoers(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "10-bad"), []byte("# c\nuser ALL=(ALL) NOPASSWD: ALL\n"), 0o440)
	os.WriteFile(filepath.Join(d, "20-open"), []byte("user ALL=(ALL) ALL\n"), 0o666)
	os.Chmod(filepath.Join(d, "20-open"), 0o666)
	none := func(context.Context) string { return "" }
	got, _ := (sudoers{[]string{filepath.Join(d, "*")}, none}).Run(context.Background(), check.Env{})
	if len(got) != 2 { // NOPASSWD ALL + world-writable
		t.Fatalf("want 2, got %+v", got)
	}
	// fallback: no readable file, but `sudo -n -l` shows NOPASSWD: ALL
	list := func(context.Context) string { return "(ALL) NOPASSWD: ALL" }
	got, _ = (sudoers{nil, list}).Run(context.Background(), check.Env{})
	if len(got) != 1 {
		t.Fatalf("sudo -l fallback: %+v", got)
	}
}

func TestBrowser(t *testing.T) {
	h := t.TempDir()
	os.Chmod(h, 0o755)
	put(t, h, ".config/google-chrome/Default/Login Data", "x", 0o644) // readable -> high
	put(t, h, ".config/chromium/Default/Login Data", "x", 0o600)      // ok
	put(t, h, ".config/chrome-flags.conf", "--password-store=basic\n", 0o600)
	got, _ := (browserData{h, ""}).Run(context.Background(), check.Env{})
	if len(got) != 2 {
		t.Fatalf("want 2, got %+v", got)
	}
}

func TestDebugPorts(t *testing.T) {
	d := t.TempDir()
	proc := func(pid, cmd string) {
		os.MkdirAll(filepath.Join(d, pid), 0o700)
		os.WriteFile(filepath.Join(d, pid, "cmdline"), []byte(cmd), 0o600)
	}
	proc("1", "/usr/bin/chrome\x00--remote-debugging-port=9222\x00--token=SECRETVALUE\x00")
	proc("2", "node\x00--inspect=0.0.0.0:9229\x00app.js\x00")
	proc("3", "node\x00--inspect\x00x.js\x00")
	proc("4", "vim\x00file\x00")
	got, _ := (debugPorts{d}).Run(context.Background(), check.Env{})
	if len(got) != 3 {
		t.Fatalf("want 3, got %+v", got)
	}
	for _, f := range got {
		if f.Evidence == "" || len(f.Evidence) > 60 || f.Evidence == "SECRETVALUE" {
			t.Errorf("bad evidence %q", f.Evidence)
		}
	}
}

func TestOpenFileInPrivateHomeIsLow(t *testing.T) {
	h := t.TempDir()
	os.Chmod(h, 0o700) // private home: other users cannot traverse into it
	put(t, h, ".aws/credentials", "aws_secret_access_key = x\n", 0o644)
	got, _ := credFiles{h}.Run(context.Background(), check.Env{})
	if len(got) != 1 || got[0].Severity.String() != "low" {
		t.Fatalf("want 1 low finding, got %+v", got)
	}
}
