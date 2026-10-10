package explain

func init() {
	Add(map[string]Entry{
		"HOST-009": {"An unencrypted disk exposes every file, key and token to anyone who steals or images the laptop. It is a standard SOC 2 / ISO 27001 device requirement.",
			"Enable LUKS full-disk encryption at install time; on an existing system encrypt /home or reinstall with encryption."},
		"HOST-010": {"A laptop that never locks hands an open session to whoever walks past; auditors expect an idle lock of 15 minutes or less.",
			"GNOME/KDE: enable automatic screen lock. Tiling WMs: run hypridle/swayidle/xss-lock with a locker."},
		"HOST-011": {"Unpatched systems are the easiest target; a replaced-but-still-running kernel means a security fix is installed but not active.",
			"Run a full system upgrade regularly and reboot after kernel updates; enable unattended security upgrades on Debian/Ubuntu."},
	})
}
