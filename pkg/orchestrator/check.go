// Package orchestrator runs all registered security checks in parallel
// and merges their findings into a single slice.
package orchestrator

import "github.com/yourorg/kubeaudit/pkg/models"
import "github.com/yourorg/kubeaudit/pkg/k8sclient"

// Check is the single interface every security check must implement.
// Stages 2-5 add real implementations; Stage 1 ships stubs so the
// pipeline compiles and runs end-to-end.
type Check interface {
	// Name returns a short, stable identifier used in logs and finding IDs.
	Name() string

	// Run inspects resources and returns zero or more findings.
	// Run must be safe to call concurrently from multiple goroutines.
	Run(resources *k8sclient.ResourceSet) []models.Finding
}
