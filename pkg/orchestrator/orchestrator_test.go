package orchestrator_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yourorg/kubeaudit/pkg/k8sclient"
	"github.com/yourorg/kubeaudit/pkg/models"
	"github.com/yourorg/kubeaudit/pkg/orchestrator"
)

// ── Test helpers ──────────────────────────────────────────────────────────────

// fixedCheck is a Check that always returns a pre-set slice of findings.
type fixedCheck struct {
	name     string
	findings []models.Finding
}

func (c *fixedCheck) Name() string { return c.name }
func (c *fixedCheck) Run(_ *k8sclient.ResourceSet) []models.Finding { return c.findings }

// countingCheck records how many times Run() has been called.
type countingCheck struct {
	name  string
	calls int64 // atomic
}

func (c *countingCheck) Name() string { return c.name }
func (c *countingCheck) Run(_ *k8sclient.ResourceSet) []models.Finding {
	atomic.AddInt64(&c.calls, 1)
	return nil
}

// slowCheck sleeps for d before returning.
type slowCheck struct {
	name  string
	sleep time.Duration
}

func (c *slowCheck) Name() string { return c.name }
func (c *slowCheck) Run(_ *k8sclient.ResourceSet) []models.Finding {
	time.Sleep(c.sleep)
	return nil
}

// emptyResources is a zero-value ResourceSet used in all tests.
var emptyResources = &k8sclient.ResourceSet{}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestOrchestratorNoChecks(t *testing.T) {
	orc := orchestrator.New(orchestrator.Options{})
	findings, err := orc.Run(context.Background(), emptyResources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestOrchestratorMergesFindings(t *testing.T) {
	f1 := models.Finding{ID: "KSA-001", Resource: models.ResourceRef{Kind: "Pod", Name: "a"}}
	f2 := models.Finding{ID: "KSA-002", Resource: models.ResourceRef{Kind: "Pod", Name: "b"}}
	f3 := models.Finding{ID: "KSA-003", Resource: models.ResourceRef{Kind: "Pod", Name: "c"}}

	orc := orchestrator.New(orchestrator.Options{})
	orc.Register(
		&fixedCheck{name: "check-a", findings: []models.Finding{f1, f2}},
		&fixedCheck{name: "check-b", findings: []models.Finding{f3}},
	)

	findings, err := orc.Run(context.Background(), emptyResources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Errorf("expected 3 findings, got %d", len(findings))
	}
}

func TestOrchestratorDeduplicates(t *testing.T) {
	// Both checks return the same (ID, resource) — should be deduplicated to 1.
	dup := models.Finding{
		ID:       "KSA-001",
		Resource: models.ResourceRef{Kind: "Pod", Name: "nginx"},
	}

	orc := orchestrator.New(orchestrator.Options{})
	orc.Register(
		&fixedCheck{name: "check-a", findings: []models.Finding{dup}},
		&fixedCheck{name: "check-b", findings: []models.Finding{dup}},
	)

	findings, err := orc.Run(context.Background(), emptyResources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 finding after dedup, got %d", len(findings))
	}
}

func TestOrchestratorRunsAllChecks(t *testing.T) {
	checks := []*countingCheck{
		{name: "c1"},
		{name: "c2"},
		{name: "c3"},
	}

	orc := orchestrator.New(orchestrator.Options{})
	for _, c := range checks {
		orc.Register(c)
	}

	_, err := orc.Run(context.Background(), emptyResources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, c := range checks {
		if atomic.LoadInt64(&c.calls) != 1 {
			t.Errorf("check %q ran %d times, want 1", c.name, c.calls)
		}
	}
}

func TestOrchestratorParallelism(t *testing.T) {
	// Five checks that each sleep 100ms. With full parallelism they should
	// complete in ~100ms, not 500ms.
	const n = 5
	const checkDuration = 100 * time.Millisecond

	orc := orchestrator.New(orchestrator.Options{MaxWorkers: n})
	for i := 0; i < n; i++ {
		orc.Register(&slowCheck{name: "slow", sleep: checkDuration})
	}

	start := time.Now()
	_, err := orc.Run(context.Background(), emptyResources)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Allow 3× the single-check duration for scheduling overhead.
	limit := checkDuration * 3
	if elapsed > limit {
		t.Errorf("expected parallel execution in <%s, took %s", limit, elapsed)
	}
}

func TestOrchestratorContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately.
	cancel()

	orc := orchestrator.New(orchestrator.Options{})
	orc.Register(&slowCheck{name: "slow", sleep: 5 * time.Second})

	_, err := orc.Run(ctx, emptyResources)
	if err == nil {
		t.Error("expected an error after context cancellation, got nil")
	}
}

func TestOrchestratorWorkerLimit(t *testing.T) {
	// With MaxWorkers=1 all checks run sequentially, but all still run.
	const n = 4
	checks := make([]*countingCheck, n)
	for i := range checks {
		checks[i] = &countingCheck{name: "c"}
	}

	orc := orchestrator.New(orchestrator.Options{MaxWorkers: 1})
	for _, c := range checks {
		orc.Register(c)
	}

	_, err := orc.Run(context.Background(), emptyResources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i, c := range checks {
		if atomic.LoadInt64(&c.calls) != 1 {
			t.Errorf("check[%d] ran %d times, want 1", i, c.calls)
		}
	}
}
