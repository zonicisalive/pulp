// Package explain holds the long-form description shown by `pulp explain <ID>`.
package explain

type Entry struct{ Why, Fix string }

// Lookup returns the entry for a check ID.
func Lookup(id string) (Entry, bool) { e, ok := entries[id]; return e, ok }

var entries = map[string]Entry{
	"DOCK-001": {"Anyone who can write to the Docker socket can start a privileged container and become root on the host.",
		"chmod 660 /var/run/docker.sock; chgrp docker /var/run/docker.sock. Only add trusted users to the docker group."},
	"DOCK-002": {"dockerd on plain TCP (port 2375) has no authentication: anyone who reaches it owns the machine.",
		"Remove the tcp:// entry from /etc/docker/daemon.json or enable TLS client authentication (2376)."},
	"DOCK-003": {"A container with docker.sock mounted, or running privileged, can escape to the host.",
		"Remove the mount; use a docker-socket-proxy with a minimal API allow-list. Replace privileged with specific cap_add entries."},
	"GIT-001": {"Secrets committed to git stay in history after deletion and are copied to every clone and fork.",
		"Rotate the credential first, then purge it with git filter-repo. Add the file to .gitignore."},
	"GIT-002": {".env files usually hold real credentials; once committed they live in history forever.",
		"git filter-repo --path .env --invert-paths, rotate everything inside, add .env to .gitignore."},
	"CORS-001": {"Wildcard or reflected origins let any website call your API from a visitor's browser; with credentials this leaks authenticated data.",
		"Allow an explicit list of origins. Never combine * or reflected origins with credentials: true."},
	"PG-001": {"pg_hba.conf 'trust' lets a connection in without a password; open to 0.0.0.0/0 it is full database takeover.",
		"Use scram-sha-256 and restrict addresses to 127.0.0.1/32 or a specific subnet."},
	"PG-002": {"A database listening on every interface (or a published 5432 in compose) is reachable from the network.",
		"listen_addresses = 'localhost'; publish as \"127.0.0.1:5432:5432\"."},
	"PG-003": {"Default passwords such as 'postgres' are the first thing attackers try.",
		"Generate a long random password, keep it in a secret store, never commit it."},
	"HOST-001": {"A group/world-readable private key can be stolen by any local user; a key with no passphrase is usable by anything that reads the file.",
		"chmod 700 ~/.ssh; chmod 600 on keys; ssh-keygen -p to add a passphrase or use a hardware token."},
	"HOST-002": {"Cloud, registry and git credential files grant access to your infrastructure when readable by others or stored in plaintext.",
		"chmod 600 the file; prefer credential helpers or short-lived SSO credentials."},
	"HOST-003": {"Shell history and rc files are plain text, backed up and synced; secrets typed or exported there leak easily.",
		"Rotate the secret, delete the line, load secrets from a secret manager. Prefix sensitive commands with a space or set HISTCONTROL=ignorespace."},
	"HOST-004": {"Without a host firewall every listening service is reachable from the local network.",
		"Enable ufw/firewalld/nftables with default-deny inbound."},
	"HOST-005": {"Databases and caches bound to all interfaces are a top cause of data theft (often with no password).",
		"Bind to 127.0.0.1 or a unix socket and block the port in the firewall."},
	"HOST-006": {"Passwordless sudo turns any code running as you (npm postinstall, a malicious extension) into root.",
		"Remove NOPASSWD: ALL; allow only specific commands. Keep sudoers files mode 0440 root:root."},
	"HOST-007": {"Browser profiles hold cookies and saved passwords; readable by other users, or with the 'basic' password store, they are easy to steal.",
		"chmod 600 profile files, 700 the profile directory; use gnome-libsecret/kwallet for Chromium."},
	"HOST-008": {"A browser remote-debugging port or Node inspector lets any local process (or any network client if exposed) control the process.",
		"Remove the flag outside active debugging; bind to 127.0.0.1 only."},
}

// Add registers entries from other batches (kept separate to keep this table readable).
func Add(m map[string]Entry) {
	for k, v := range m {
		entries[k] = v
	}
}
