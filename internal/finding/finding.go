// Package finding defines scan results. New is the only constructor so
// redaction cannot be skipped.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var names = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string { return names[s] }

func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func ParseSeverity(v string) (Severity, error) {
	for i, n := range names {
		if n == v {
			return Severity(i), nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q", v)
}

type Location struct {
	Path   string `json:"path,omitempty"`
	Line   int    `json:"line,omitempty"`
	Commit string `json:"commit,omitempty"`
}

type Finding struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Confidence  string   `json:"confidence"`
	Title       string   `json:"title"`
	Location    Location `json:"location"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation"`
	Fingerprint string   `json:"fingerprint"`
}

// Input is what a check supplies. Secret=true redacts Evidence.
type Input struct {
	ID, Title, Evidence, Remediation, Confidence string
	Severity                                     Severity
	Location                                     Location
	Secret                                       bool
}

func New(in Input) Finding {
	ev := in.Evidence
	if in.Secret {
		ev = Redact(ev)
	}
	if in.Confidence == "" {
		in.Confidence = "high"
	}
	sum := sha256.Sum256([]byte(in.ID + "|" + in.Location.Path + "|" + ev))
	return Finding{in.ID, in.Severity, in.Confidence, in.Title, in.Location, ev,
		in.Remediation, hex.EncodeToString(sum[:])}
}

// Redact keeps first 2 + last 2 chars; values <= 8 chars are fully masked.
func Redact(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:2] + "****" + s[len(s)-2:]
}
