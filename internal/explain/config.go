package explain

func init() {
	Add(map[string]Entry{
		"DB-001": {"Redis with no password on a reachable interface is routinely hijacked (data theft, then code execution through config/ module tricks).",
			"requirepass or ACL users, bind 127.0.0.1, protected-mode yes."},
		"DB-002": {"MongoDB ships with auth off. Reachable without it, the whole database is public; even locally any process of yours can read it.",
			"security.authorization: enabled, create users, bindIp 127.0.0.1."},
		"DB-003": {"skip-grant-tables disables authentication entirely; binding to all interfaces exposes the server to the network.",
			"Remove skip-grant-tables, bind-address = 127.0.0.1, local_infile = 0."},
		"DB-004": {"Compose files turn throwaway containers into network-exposed databases with empty or default passwords; many real breaches start here.",
			"Bind published ports to 127.0.0.1 and use long random passwords from a secret store."},
		"GIT-003": {"A .env that is neither committed nor ignored is one careless `git add .` from being published.",
			"Add .env* to .gitignore and keep only a .env.example."},
		"HOST-012": {"StrictHostKeyChecking no and discarded known_hosts hide man-in-the-middle attacks; ForwardAgent yes on all hosts lets a hacked server use your SSH keys.",
			"Use accept-new, keep known_hosts, replace agent forwarding with ProxyJump."},
		"HOST-013": {"A running sshd that allows root password logins, empty passwords or any password auth invites brute-force takeover.",
			"PermitRootLogin prohibit-password, PasswordAuthentication no, MaxAuthTries 3."},
		"HOST-014": {"Global git settings can silently store passwords in plaintext or turn off TLS and ownership checks for every repository.",
			"Use a credential helper (libsecret), remove http.sslVerify=false and safe.directory=*."},
	})
}
