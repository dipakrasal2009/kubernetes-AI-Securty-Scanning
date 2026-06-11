package models_test

import (
	"encoding/json"
	"testing"

	"github.com/yourorg/kubeaudit/pkg/models"
)

func TestSeverityString(t *testing.T) {
	cases := []struct {
		sev  models.Severity
		want string
	}{
		{models.SeverityLow, "LOW"},
		{models.SeverityMedium, "MEDIUM"},
		{models.SeverityHigh, "HIGH"},
		{models.SeverityCritical, "CRITICAL"},
	}
	for _, tc := range cases {
		if got := tc.sev.String(); got != tc.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tc.sev, got, tc.want)
		}
	}
}

func TestSeverityMarshalJSON(t *testing.T) {
	f := models.Finding{
		ID:       "KSA-001",
		Severity: models.SeverityCritical,
		Resource: models.ResourceRef{Kind: "Pod", Namespace: "default", Name: "nginx"},
		Message:  "container runs as root",
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if got := out["severity"]; got != "CRITICAL" {
		t.Errorf("severity = %v, want CRITICAL", got)
	}
}

func TestResourceRefString(t *testing.T) {
	cases := []struct {
		ref  models.ResourceRef
		want string
	}{
		{models.ResourceRef{Kind: "Pod", Namespace: "default", Name: "nginx"}, "Pod/default/nginx"},
		{models.ResourceRef{Kind: "ClusterRole", Name: "admin"}, "ClusterRole/admin"},
	}
	for _, tc := range cases {
		if got := tc.ref.String(); got != tc.want {
			t.Errorf("ResourceRef.String() = %q, want %q", got, tc.want)
		}
	}
}

func TestBuildSummary(t *testing.T) {
	findings := []models.Finding{
		{ID: "KSA-001", Severity: models.SeverityCritical},
		{ID: "KSA-002", Severity: models.SeverityHigh},
		{ID: "KSA-003", Severity: models.SeverityHigh},
		{ID: "KSA-004", Severity: models.SeverityMedium},
		{ID: "KSA-005", Severity: models.SeverityLow},
	}

	summary := models.BuildSummary("https://k8s.example.com", "prod", 42, findings)

	if summary.CountBySev["CRITICAL"] != 1 {
		t.Errorf("CRITICAL count = %d, want 1", summary.CountBySev["CRITICAL"])
	}
	if summary.CountBySev["HIGH"] != 2 {
		t.Errorf("HIGH count = %d, want 2", summary.CountBySev["HIGH"])
	}
	if summary.CountBySev["MEDIUM"] != 1 {
		t.Errorf("MEDIUM count = %d, want 1", summary.CountBySev["MEDIUM"])
	}
	if summary.CountBySev["LOW"] != 1 {
		t.Errorf("LOW count = %d, want 1", summary.CountBySev["LOW"])
	}
	if summary.TotalChecked != 42 {
		t.Errorf("TotalChecked = %d, want 42", summary.TotalChecked)
	}
	if summary.ClusterContext != "https://k8s.example.com" {
		t.Errorf("ClusterContext = %q, want https://k8s.example.com", summary.ClusterContext)
	}
}
