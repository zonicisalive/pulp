package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zonicisalive/pulp/internal/finding"
)

func TestSARIFShapeAndNoSecret(t *testing.T) {
	secret := "AKIA" + "ABCDEFGHIJKLMNOP"
	f := finding.New(finding.Input{ID: "GIT-001", Severity: finding.Critical, Title: "t", Evidence: secret,
		Secret: true, Location: finding.Location{Path: "a.js", Line: 3}, Remediation: "rotate"})
	var buf bytes.Buffer
	if err := SARIF(&buf, "x", []finding.Finding{f}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), secret) {
		t.Fatal("raw secret leaked into SARIF")
	}
	j, _ := json.Marshal(f)
	if strings.Contains(string(j), secret) {
		t.Fatal("raw secret leaked into JSON")
	}
	var d struct {
		Version string
		Runs    []struct{ Results []struct{ Level string } }
	}
	if json.Unmarshal(buf.Bytes(), &d) != nil || d.Version != "2.1.0" || d.Runs[0].Results[0].Level != "error" {
		t.Errorf("bad SARIF: %s", buf.String())
	}
}
