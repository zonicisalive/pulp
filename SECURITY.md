# Security policy

Please report vulnerabilities **privately** through GitHub: *Security* tab > *Report a vulnerability*. Do not open a public issue for a security bug.

pulp is a read-only scanner that runs locally and makes no network calls. Reports I especially want to hear about:
- a way for a crafted repository, config or history file to make pulp execute code, write files, or hang;
- a case where a full secret (not the redacted form) reaches output, JSON, SARIF or an ignore file;
- a `.pulp-ignore` or baseline behavior that hides findings unexpectedly.

I will acknowledge a report within a few days. Only the latest release is supported.
