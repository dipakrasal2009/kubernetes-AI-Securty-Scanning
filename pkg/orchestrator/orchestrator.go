package orchestrator

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/yourorg/kubeaudit/pkg/k8sclient"
	"github.com/yourorg/kubeaudit/pkg/models"
)

// Options controls orchestrator behaviour.
type Options struct {
	// MaxWorkers caps the number of goroutines running checks concurrently.
	// 0 means one goroutine per registered check (fully parallel).
	MaxWorkers int

	// Verbose enables per-check timing logs.
	Verbose bool
}

// Orchestrator manages a registry of checks and executes them in parallel.
type Orchestrator struct {
	checks  []Check
	options Options
}

// New creates an Orchestrator with the given options.
func New(opts Options) *Orchestrator {
	return &Orchestrator{options: opts}
}

// Register adds one or more checks to the registry.
// Checks are run in registration order when capacity is limited.
func (o *Orchestrator) Register(checks ...Check) {
	o.checks = append(o.checks, checks...)
}

// Run executes all registered checks concurrently against the provided
// ResourceSet and returns the merged, deduplicated slice of findings.
//
// Architecture:
//
//	jobs channel  ──►  worker goroutine pool  ──►  results channel  ──►  merger
//
// The jobs channel is buffered to the number of registered checks so the
// dispatcher never blocks.  The results channel is unbuffered; the merger
// goroutine reads from it as workers send.  A sync.WaitGroup signals when all
// workers are done so the merger can close the results channel cleanly.
func (o *Orchestrator) Run(ctx context.Context, resources *k8sclient.ResourceSet) ([]models.Finding, error) {
	if len(o.checks) == 0 {
		return nil, nil
	}

	// ── 1. Determine worker pool size ────────────────────────────────────────
	numWorkers := o.options.MaxWorkers
	if numWorkers <= 0 || numWorkers > len(o.checks) {
		numWorkers = len(o.checks) // fully parallel by default
	}

	// ── 2. Create channels ────────────────────────────────────────────────────
	// jobs is buffered: the dispatcher writes all checks without blocking.
	jobs := make(chan Check, len(o.checks))

	// results is unbuffered: the merger goroutine must be ready before workers send.
	results := make(chan []models.Finding)

	// ── 3. Start merger goroutine ─────────────────────────────────────────────
	// It collects all findings slices from results and sends the merged slice
	// on merged once results is closed.
	merged := make(chan []models.Finding, 1)
	go func() {
		var all []models.Finding
		for batch := range results {
			all = append(all, batch...)
		}
		merged <- all
	}()

	// ── 4. Start worker pool ──────────────────────────────────────────────────
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for check := range jobs {
				// Honour context cancellation between checks.
				select {
				case <-ctx.Done():
					return
				default:
				}

				findings := runCheck(ctx, check, resources, o.options.Verbose)
				results <- findings
			}
		}()
	}

	// ── 5. Dispatch all checks onto the jobs channel ──────────────────────────
	for _, c := range o.checks {
		jobs <- c
	}
	close(jobs) // signals workers: no more jobs

	// ── 6. Wait for all workers, then close results ───────────────────────────
	// This is done in a separate goroutine so the merger can keep draining.
	go func() {
		wg.Wait()
		close(results) // signals merger: no more results
	}()

	// ── 7. Collect merged findings ────────────────────────────────────────────
	select {
	case findings := <-merged:
		return deduplicate(findings), nil
	case <-ctx.Done():
		return nil, fmt.Errorf("scan cancelled: %w", ctx.Err())
	}
}

// runCheck executes a single check and recovers from panics.
func runCheck(ctx context.Context, c Check, resources *k8sclient.ResourceSet, verbose bool) []models.Finding {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[orchestrator] check %q panicked: %v", c.Name(), r)
		}
	}()

	start := time.Now()
	findings := c.Run(resources)
	elapsed := time.Since(start)

	if verbose {
		log.Printf("[orchestrator] check %-30s  findings=%-3d  duration=%s",
			c.Name(), len(findings), elapsed.Round(time.Millisecond))
	}

	return findings
}

// deduplicate removes findings with identical (ID, Resource) pairs,
// keeping the first occurrence.
func deduplicate(findings []models.Finding) []models.Finding {
	seen := make(map[string]struct{}, len(findings))
	out := make([]models.Finding, 0, len(findings))
	for _, f := range findings {
		key := f.ID + "|" + f.Resource.String()
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			out = append(out, f)
		}
	}
	return out
}
