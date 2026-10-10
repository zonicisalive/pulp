package host

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zonicisalive/pulp/internal/check"
)

func put(t *testing.T, home, rel, body string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(home, rel)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	os.Chmod(p, mode)
}

// split so pulp does not flag its own test fixtures
const begin = "-----BEGIN " + ""

// openssh-key-v1 header, cipher "none" vs "aes256-ctr" (only the part encrypted() reads)
func sshBlob(cipher string) string {
	raw := "openssh-key-v1\x00\x00\x00\x00" + string(rune(len(cipher))) + cipher
	return begin + "OPENSSH PRIVATE KEY-----\n" + b64(raw) + "\n-----END OPENSSH PRIVATE KEY-----\n"
}

func TestSSH(t *testing.T) {
	h := t.TempDir()
	os.MkdirAll(filepath.Join(h, ".ssh"), 0o700)
	put(t, h, ".ssh/id_open", sshBlob("none"), 0o644)                                       // open perms + no passphrase
	put(t, h, ".ssh/id_ok", sshBlob("aes256-ctr"), 0o600)                                   // clean
	put(t, h, ".ssh/id_ok.pub", "ssh-ed25519 AAAA", 0o644)                                  // public key ignored
	put(t, h, ".ssh/id_pem", begin+"RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n", 0o600) // encrypted PEM
	got, _ := sshKeys{h}.Run(context.Background(), check.Env{})
	if len(got) != 2 {
		t.Fatalf("want 2 (perms + no passphrase on id_open), got %d: %+v", len(got), got)
	}
	for _, f := range got {
		if !strings.HasSuffix(f.Location.Path, "id_open") || strings.Contains(f.Location.Path, h) {
			t.Errorf("bad path %q", f.Location.Path)
		}
	}
}

func TestCreds(t *testing.T) {
	h := t.TempDir()
	os.Chmod(h, 0o755)
	put(t, h, ".aws/credentials", "aws_secret_access_key = x\n", 0o644) // open -> high
	put(t, h, ".npmrc", "//r/:_authToken=abc\n", 0o600)                 // ok
	put(t, h, ".git-credentials", "https://u:p@github.com\n", 0o600)    // plaintext -> medium
	put(t, h, ".netrc", "nothing here\n", 0o644)                        // no marker -> ignored
	got, _ := credFiles{h}.Run(context.Background(), check.Env{})
	if len(got) != 2 {
		t.Fatalf("want 2, got %d: %+v", len(got), got)
	}
}

func TestShell(t *testing.T) {
	h := t.TempDir()
	key := "AKIA" + "ABCDEFGHIJKLMNOP"
	put(t, h, ".bash_history", "ls\nexport DB_PASSWORD=hunter2hunter2\naws s3 ls --key "+key+"\nexport TOKEN=$(pass show t)\nmysql -u r -pSuperS3cret db\n", 0o600)
	put(t, h, ".zshrc", "export API_TOKEN=\"PASTE_YOUR_TOKEN_HERE\"\n", 0o600)
	got, _ := shellSecrets{h}.Run(context.Background(), check.Env{})
	if len(got) != 3 { // DB_PASSWORD export, AWS key, mysql -p ; $(...) and placeholder ignored
		t.Fatalf("want 3, got %d: %+v", len(got), got)
	}
	for _, f := range got {
		if strings.Contains(f.Evidence, "hunter2") || strings.Contains(f.Evidence, key) {
			t.Errorf("leaked: %q", f.Evidence)
		}
	}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
