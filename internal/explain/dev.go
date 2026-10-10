package explain

func init() {
	Add(map[string]Entry{
		"DEV-001": {"Debug modes expose stack traces, settings and, with Flask's Werkzeug debugger, an interactive console that runs code on the server. They are fine locally and fatal when they ship.",
			"Drive debug flags from environment variables that default to off; keep SECRET_KEY out of source."},
		"DEV-002": {"Dev servers and `python -m http.server` bind all interfaces by default, so anyone on the same Wi-Fi can read your project or use the dev tooling.",
			"Bind to 127.0.0.1; expose deliberately through a tunnel when you need to share."},
		"DEV-003": {"Anything under public/ or static/ is downloadable. Committed .env, keys, SQL dumps or a .git folder there hand attackers the whole project.",
			"Serve only a dedicated public directory and keep secrets and dumps outside it."},
		"DEV-004": {"Turning off certificate verification makes every HTTPS call open to man-in-the-middle attacks, and the flag tends to outlive the debugging session.",
			"Trust your CA explicitly (NODE_EXTRA_CA_CERTS, verify=<bundle>, RootCAs) instead of disabling checks."},
	})
}
