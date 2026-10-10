package explain

func init() {
	Add(map[string]Entry{
		"CI-001": {"CI runs with your secrets and write tokens. Interpolating PR text into shell, running PR code under pull_request_target, or using floating action tags lets an outsider (or a hijacked action) take them.",
			"Pass untrusted text via env:, avoid pull_request_target for PR code, set minimal permissions:, and pin actions to full commit SHAs."},
		"DOCK-004": {"Root containers, floating :latest bases, piped installers and secrets in ENV/ARG are the usual ways images become a foothold or leak credentials.",
			"Pin base image versions/digests, add a non-root USER, verify downloads, and use BuildKit secrets."},
		"PKG-001": {"Install-time scripts, plain-HTTP registries, unpinned versions and missing lockfiles let a dependency swap or typosquat run code on every developer machine and CI runner.",
			"Commit lockfiles, use https registries, keep tokens in env vars, and keep install hooks free of network/eval."},
	})
}
