package models

import "fmt"

// Severity represents the risk level of a security finding.
type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// Category groups findings by check domain.
type Category string

const (
	CategoryContainer Category = "container"
	CategoryNetwork   Category = "network"
	CategoryRBAC      Category = "rbac"
	CategoryResource  Category = "resource"
	CategorySecret    Category = "secret"
	CategoryImage     Category = "image"
)

// ResourceRef uniquely identifies a Kubernetes resource.
type ResourceRef struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

func (r ResourceRef) String() string {
	if r.Namespace != "" {
		return fmt.Sprintf("%s/%s/%s", r.Kind, r.Namespace, r.Name)
	}
	return fmt.Sprintf("%s/%s", r.Kind, r.Name)
}

// Finding is the core output unit produced by every check.
// Every field is intentionally exported so JSON marshalling works out of the box.
type Finding struct {
	// ID is a stable machine-readable identifier e.g. "KSA-001".
	ID string `json:"id"`

	// CheckName is the human-readable name of the check that produced this finding.
	CheckName string `json:"check_name"`

	// Category groups the finding by domain (container, rbac, network …).
	Category Category `json:"category"`

	// Severity is the risk level: LOW / MEDIUM / HIGH / CRITICAL.
	Severity Severity `json:"severity"`

	// Resource is the Kubernetes object this finding applies to.
	Resource ResourceRef `json:"resource"`

	// Message is a one-sentence human-readable description of the problem.
	Message string `json:"message"`

	// Remediation is a concrete, actionable fix the user should apply.
	Remediation string `json:"remediation"`

	// Details holds optional key-value pairs with extra context (field paths, values, etc.).
	Details map[string]string `json:"details,omitempty"`
}

// ScanSummary wraps the full result of one scan run.
type ScanSummary struct {
	ClusterContext string    `json:"cluster_context"`
	Namespace      string    `json:"namespace,omitempty"`
	TotalChecked   int       `json:"total_resources_checked"`
	Findings       []Finding `json:"findings"`
	CountBySev     map[string]int `json:"count_by_severity"`
}

// BuildSummary produces a ScanSummary from a flat slice of findings.
func BuildSummary(ctx, ns string, checked int, findings []Finding) ScanSummary {
	counts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}
	for _, f := range findings {
		counts[f.Severity.String()]++
	}
	return ScanSummary{
		ClusterContext: ctx,
		Namespace:      ns,
		TotalChecked:   checked,
		Findings:       findings,
		CountBySev:     counts,
	}
}
