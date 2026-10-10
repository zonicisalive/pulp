# pulp

A fast security-hardening scanner for developer machines and projects. One static binary, no dependencies, everything runs locally.

```
$ pulp scan
[high    ] GIT-001  AWS access key in git history
           config/dev.js @a1b2c3d  AK****LE
           fix: Rotate the credential first, then purge it with git filter-repo.
[medium  ] HOST-009  Neither / nor /home sits on an encrypted (dm-crypt) device
           ...

Score 82/100 · 1 high · 3 medium · 2 ignored
```

It looks for the misconfigurations that actually get developers breached: a world-writable Docker socket, secrets left in git history, wildcard CORS, a Postgres that trusts everyone, `FLASK debug=True` on `0.0.0.0`, an unencrypted laptop disk, risky GitHub Actions, and more (35 checks, listed below).

**Status:** early (v0.1). Linux only for now; macOS and Windows are planned.

## Install

```sh
go install github.com/zonicisalive/pulp/cmd/pulp@latest      # needs Go 1.27+
```

or from source:

```sh
git clone https://github.com/zonicisalive/pulp && cd pulp
CGO_ENABLED=0 go build -o pulp ./cmd/pulp && sudo install pulp /usr/local/bin/
```

Prebuilt Linux binaries (amd64, arm64) are attached to each GitHub release.

## Usage

```sh
pulp scan                    # project in . plus this machine
pulp scan ~/code/myapp       # another project
pulp scan --skip host        # project checks only (use this in CI)
pulp scan --only docker,PG-001
pulp scan --fail-on medium   # exit 1 at or above this severity (default: high)
pulp scan --format json|sarif|compliance      # or --json / --sarif
pulp explain HOST-003        # why it matters, how to fix
pulp list-checks
```

Exit codes: `0` clean (below `--fail-on`), `1` findings at or above `--fail-on`, `2` tool error.

## Privacy: read this before you run it

**Pulp makes no network calls and sends nothing anywhere.** (An optional cloud reporter is planned; it is not built, and it will be opt-in.)

By default `pulp scan` also audits **the machine you run it on**. The `host` checks read, locally:

- `~/.ssh` (key files, to check permissions and whether a key has a passphrase) and `~/.ssh/config`
- credential files such as `~/.aws/credentials`, `~/.kube/config`, `~/.docker/config.json`, `~/.npmrc`, `~/.git-credentials`, `~/.gitconfig`
- **shell history and rc files** (to find secrets typed or exported there)
- file permissions of browser profile databases (not their contents)
- `/etc/ssh/sshd_config`, `/etc/sudoers*` (if readable), and `/proc` (listening ports, process command lines)

and run these commands: `systemctl is-active`, `lsblk`, `gsettings`/`kreadconfig`, and **`sudo -n -l`** (never prompts; it appears in your auth log).

Findings never contain full secrets: evidence is redacted to the first and last two characters (values of 8 characters or fewer are fully masked), and paths under your home are shown as `~/...`.

Use `pulp scan --skip host` to scan only the project, e.g. in CI.

## Checks

| ID | Category | What it flags |
|---|---|---|
| CORS-001 | cors | Overly permissive CORS policy |
| DOCK-001 | docker | Docker socket permissions too open |
| DOCK-002 | docker | Docker daemon exposed on unauthenticated TCP |
| DOCK-003 | docker | Compose service mounts docker.sock or runs privileged |
| PG-001 | postgres | pg_hba.conf allows trust auth or world-open access |
| PG-002 | postgres | Postgres listens on all interfaces or publishes 5432 publicly |
| PG-003 | postgres | Default or weak Postgres credentials in config |
| DB-001 | db | Redis without password or exposed to the network |
| DB-002 | db | MongoDB authentication disabled or exposed |
| DB-003 | db | MySQL/MariaDB insecure server option |
| DB-004 | db | Compose publishes a data store or sets empty/weak credentials |
| DEV-001 | devserver | Framework debug mode or insecure default enabled |
| DEV-002 | devserver | Dev server or file server bound to all interfaces |
| DEV-003 | devserver | Secrets or source served from a public/static directory |
| DEV-004 | devserver | TLS certificate verification disabled |
| CI-001 | ci | Risky GitHub Actions workflow |
| DOCK-004 | docker | Insecure Dockerfile practice |
| PKG-001 | pkg | Package manager config weakens supply-chain security |
| GIT-001 | git | Secret committed in git history |
| GIT-002 | git | .env file committed to git history |
| GIT-003 | git | .env file exists but is not in .gitignore |
| HOST-009 | host | Disk is not encrypted (LUKS/dm-crypt) |
| HOST-010 | host | No automatic screen lock |
| HOST-011 | host | System updates overdue or reboot pending |
| HOST-013 | host | Insecure sshd setting on a machine running sshd |
| HOST-012 | host | Insecure SSH client option |
| HOST-014 | host | Insecure global git setting |
| HOST-001 | host | SSH directory or private key too open / unencrypted |
| HOST-002 | host | Credential file readable by others or stored in plaintext |
| HOST-003 | host | Secret in shell history or rc file |
| HOST-004 | host | No active host firewall |
| HOST-005 | host | Database/cache port listening on all interfaces |
| HOST-006 | host | Passwordless sudo or writable sudoers |
| HOST-008 | host | Debug/remote-control port enabled on a running process |
| HOST-007 | host | Browser credential store exposed |

Severity is `critical > high > medium > low > info`. Text-pattern checks (CORS, dev servers, Dockerfile, Actions, compose) are heuristics: expect to ignore some findings.

## Ignoring findings

Put a `.pulp-ignore` in the scanned project (or `~/.config/pulp/ignore` for machine-wide rules). One rule per line, `#` starts a comment:

```
<64-hex fingerprint>              # one exact finding
GIT-001 commit:e0cc948            # a check, limited to a commit prefix
CORS-001 demo/*                   # a check, limited to a path (trailing * = prefix)
DOCK-003                          # a whole check
```

`pulp baseline` records every current finding so only new ones are reported afterwards. Suppressed findings are always counted in the summary (`2 ignored`); `--no-ignore` shows everything.

## Stop secrets before they are committed

```sh
pulp install-hook      # writes .git/hooks/pre-commit running `pulp staged`
```

`pulp staged` scans only the staged diff (milliseconds) and blocks the commit on a secret or a staged `.env`. Bypass once with `git commit --no-verify`.

## CI

```yaml
- run: pulp scan --skip host --sarif > pulp.sarif
- uses: github/codeql-action/upload-sarif@<sha>
  with: { sarif_file: pulp.sarif }
```

Pin actions to full commit SHAs (pulp's CI-001 check will tell you if you do not).

## Compliance evidence

`pulp scan --format compliance` writes a Markdown report mapping each check to SOC 2 / ISO 27001 controls with a PASS/FAIL per check. The mapping is indicative, a help for gathering evidence, not audit advice. A check that cannot inspect the machine (no systemd, inside a container) reports no findings, which the report shows as PASS.

## Limits

- Linux only. Pattern checks are line-based regexes, not full parsers.
- Git history scan covers the newest 1000 commits.
- Firewall detection asks systemd (`ufw`, `firewalld`, `nftables`, `iptables`); a ruleset loaded some other way is not seen.
- Secret detection is regex plus entropy; known documentation placeholders (`AKIA...EXAMPLE`, `PASTE_YOUR_KEY`) are ignored.

## Development

```sh
go vet ./... && go test ./...
```

Add a check: implement `check.Check`, `check.Register` it in an `init`, add a `pulp explain` entry (`internal/explain`) and a control mapping (`internal/report/compliance.go`). Tests fail until you do.

## License

Apache 2.0, see [LICENSE](LICENSE).
