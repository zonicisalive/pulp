// Package secrets detects credentials in a line of text (shared by git-history and host checks).
package secrets

import (
	"math"
	"regexp"
)

type Match struct {
	Name       string
	Value      string
	Confidence string
}

type rule struct {
	name       string
	re         *regexp.Regexp
	confidence string
	minEntropy float64
}

// Every regex has exactly one capture group: the secret value.
var rules = []rule{
	{"AWS access key", regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`), "high", 0},
	{"GitHub token", regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,})\b`), "high", 0},
	{"Stripe live key", regexp.MustCompile(`\b(sk_live_[0-9a-zA-Z]{24,})\b`), "high", 0},
	{"Slack token", regexp.MustCompile(`\b(xox[baprs]-[A-Za-z0-9-]{10,})\b`), "high", 0},
	{"Google API key", regexp.MustCompile(`\b(AIza[0-9A-Za-z_-]{35})\b`), "high", 0},
	{"Private key", regexp.MustCompile(`(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)`), "high", 0},
	{"Generic secret assignment", regexp.MustCompile(`(?i)(?:secret|token|passwd|password|api[_-]?key)["']?\s*[:=]\s*["']([A-Za-z0-9/+_=-]{20,})["']`), "medium", 3.5},
}

var placeholder = regexp.MustCompile(`(?i)EXAMPLE$|paste|your[_-]|placeholder|changeme|replace|insert|dummy|xxxx|todo`)

// IsPlaceholder reports whether v looks like a docs/template value rather than a real secret.
func IsPlaceholder(v string) bool { return placeholder.MatchString(v) }

// Scan returns the first secret found in line, ignoring docs placeholders.
func Scan(line string) (Match, bool) {
	for _, r := range rules {
		m := r.re.FindStringSubmatch(line)
		if m == nil || placeholder.MatchString(m[1]) || (r.minEntropy > 0 && entropy(m[1]) < r.minEntropy) {
			continue
		}
		return Match{r.name, m[1], r.confidence}, true
	}
	return Match{}, false
}

func entropy(s string) float64 {
	n := float64(len(s))
	cnt := map[rune]float64{}
	for _, r := range s {
		cnt[r]++
	}
	var h float64
	for _, c := range cnt {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}
