package reporter_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yourorg/kubeaudit/pkg/models"
	"github.com/yourorg/kubeaudit/pkg/reporter"
)

func makeSummary(findings ...models.Finding) models.ScanSummary {
	return models.BuildSummary("https://k8s.example.com", "", len(findings), findings)
}

func TestJSONReporterOutput(t *testing.T) {
	var buf bytes.Buffer
	r := reporter.NewJSONReporter(&buf, false)

	summary := makeSummary(models.Finding{
		ID:       "KSA-001",
		Severity: models.SeverityHigh,
		Resource: models.ResourceRef{Kind: "Pod", Namespace: "default", Name: "nginx"},
		Message:  "container runs as root",
	})

	if err := r.Report(summary); err != nil {
		t.Fatalf("Report failed: %v", err)
	}

	var out map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}

	findings, ok := out["findings"].([]interface{})
	if !ok {
		t.Fatal("findings field missing or wrong type")
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
}

func TestJSONReporterPretty(t *testing.T) {
	var buf bytes.Buffer
	r := reporter.NewJSONReporter(&buf, true)

	if err := r.Report(makeSummary()); err != nil {
		t.Fatalf("Report failed: %v", err)
	}

	// Pretty output must contain newlines and indentation.
	if !strings.Contains(buf.String(), "\n  ") {
		t.Error("pretty output does not appear to be indented")
	}
}

func TestExitCode(t *testing.T) {
	cases := []struct {
		name     string
		findings []models.Finding
		want     int
	}{
		{
			name:     "no findings",
			findings: nil,
			want:     0,
		},
		{
			name:     "low only",
			findings: []models.Finding{{Severity: models.SeverityLow}},
			want:     1,
		},
		{
			name:     "medium only",
			findings: []models.Finding{{Severity: models.SeverityMedium}},
			want:     1,
		},
		{
			name:     "high present",
			findings: []models.Finding{{Severity: models.SeverityMedium}, {Severity: models.SeverityHigh}},
			want:     2,
		},
		{
			name:     "critical present",
			findings: []models.Finding{{Severity: models.SeverityHigh}, {Severity: models.SeverityCritical}},
			want:     3,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			summary := makeSummary(tc.findings...)
			if got := reporter.ExitCode(summary); got != tc.want {
				t.Errorf("ExitCode() = %d, want %d", got, tc.want)
			}
		})
	}
}
