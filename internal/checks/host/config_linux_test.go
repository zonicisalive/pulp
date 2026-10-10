//go:build linux

package host

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/zonicisalive/pulp/internal/check"
)

func TestSSHClient(t *testing.T) {
	h := t.TempDir()
	put(t, h, ".ssh/config", `Host *
  ForwardAgent yes
  StrictHostKeyChecking no
Host build
  StrictHostKeyChecking no
  ForwardAgent yes
Host ok
  StrictHostKeyChecking accept-new
`, 0o600)
	got, _ := sshClient{h}.Run(context.Background(), check.Env{})
	// Host *: 2 medium; build: strict low + agent info
	if len(got) != 4 {
		t.Fatalf("want 4, got %+v", got)
	}
	med := 0
	for _, f := range got {
		if f.Severity.String() == "medium" {
			med++
		}
	}
	if med != 2 {
		t.Errorf("want 2 medium (global), got %d", med)
	}
}

func TestSSHD(t *testing.T) {
	d := t.TempDir()
	os.MkdirAll(filepath.Join(d, "sshd_config.d"), 0o755)
	os.WriteFile(filepath.Join(d, "sshd_config"), []byte("PermitRootLogin yes\nPasswordAuthentication yes\nX11Forwarding no\n"), 0o600)
	os.WriteFile(filepath.Join(d, "sshd_config.d", "10.conf"), []byte("PasswordAuthentication no\n"), 0o600) // drop-in wins
	globs := []string{filepath.Join(d, "sshd_config.d/*.conf"), filepath.Join(d, "sshd_config")}
	listen := filepath.Join(d, "tcp")
	os.WriteFile(listen, []byte("sl local st\n0: 00000000:0016 00000000:0000 0A\n"), 0o600) // 0x16 = 22
	got, _ := (sshdConfig{globs, []string{listen}}).Run(context.Background(), check.Env{})
	if len(got) != 1 || got[0].Severity.String() != "high" { // root login only; password auth overridden to no
		t.Fatalf("want only root login, got %+v", got)
	}
	idle := filepath.Join(d, "tcp-idle")
	os.WriteFile(idle, []byte("sl local st\n"), 0o600)
	if got, _ := (sshdConfig{globs, []string{idle}}).Run(context.Background(), check.Env{}); len(got) != 0 {
		t.Errorf("sshd not listening must stay silent: %+v", got)
	}
}

func TestGitConfig(t *testing.T) {
	h := t.TempDir()
	put(t, h, ".gitconfig", `[user]
	name = x
[credential]
	helper = store
[http "https://corp.example"]
	sslVerify = false
[safe]
	directory = *
[core]
	sshCommand = ssh -o StrictHostKeyChecking=no
[credential "https://x"]
	helper = cache
`, 0o600)
	got, _ := gitConfig{h}.Run(context.Background(), check.Env{})
	if len(got) != 4 {
		t.Fatalf("want 4, got %+v", got)
	}
}
