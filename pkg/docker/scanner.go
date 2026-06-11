package docker

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/yourorg/kubeaudit/pkg/models"
)

// ScanOptions controls the Docker scanner behaviour.
type ScanOptions struct {
	SocketPath string
	Verbose    bool
	// MaxWorkers caps parallel check goroutines. 0 = one per check.
	MaxWorkers int
}

// ScanResult holds the findings from a full Docker scan.
type ScanResult struct {
	SocketPath        string           `json:"socket_path"`
	ContainersScanned int              `json:"containers_scanned"`
	Findings          []models.Finding `json:"findings"`
	CountBySev        map[string]int   `json:"count_by_severity"`
	FetchErrors       []string         `json:"fetch_errors,omitempty"`
}

// Scan connects to Docker, fetches all running containers, and runs all
// built-in checks in parallel, returning a ScanResult.
func Scan(ctx context.Context, opts ScanOptions) (*ScanResult, error) {
	socketPath := opts.SocketPath
	if socketPath == "" {
		socketPath = DefaultSocket
	}

	// Connect
	client, err := NewClient(socketPath)
	if err != nil {
		return nil, fmt.Errorf("docker: %w", err)
	}

	if opts.Verbose {
		log.Printf("[docker] connected to %s", socketPath)
	}

	// Fetch
	rs, fetchErrs := client.FetchAll()
	result := &ScanResult{
		SocketPath:        socketPath,
		ContainersScanned: len(rs.Containers),
	}
	for _, e := range fetchErrs {
		result.FetchErrors = append(result.FetchErrors, e.Error())
		if opts.Verbose {
			log.Printf("[docker] fetch warning: %v", e)
		}
	}

	if opts.Verbose {
		log.Printf("[docker] fetched %d containers, %d images", len(rs.Containers), len(rs.Images))
	}

	// Run checks in parallel
	checks := AllDockerChecks()
	numWorkers := opts.MaxWorkers
	if numWorkers <= 0 || numWorkers > len(checks) {
		numWorkers = len(checks)
	}

	jobs := make(chan DockerCheck, len(checks))
	results := make(chan []models.Finding)
	merged := make(chan []models.Finding, 1)

	// merger goroutine
	go func() {
		var all []models.Finding
		for batch := range results {
			all = append(all, batch...)
		}
		merged <- all
	}()

	// worker pool
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for check := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				start := time.Now()
				findings := check.Run(rs)
				if opts.Verbose {
					log.Printf("[docker] check %-35s  findings=%-3d  duration=%s",
						check.Name(), len(findings), time.Since(start).Round(time.Millisecond))
				}
				results <- findings
			}
		}()
	}

	for _, c := range checks {
		jobs <- c
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	select {
	case findings := <-merged:
		result.Findings = dedup(findings)
	case <-ctx.Done():
		return nil, fmt.Errorf("docker scan cancelled: %w", ctx.Err())
	}

	// Count by severity
	counts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	for _, f := range result.Findings {
		counts[f.Severity.String()]++
	}
	result.CountBySev = counts

	return result, nil
}

func dedup(findings []models.Finding) []models.Finding {
	seen := make(map[string]struct{}, len(findings))
	out := make([]models.Finding, 0, len(findings))
	for _, f := range findings {
		key := f.ID + "|" + f.Resource.String()
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			out = append(out, f)
		}
	}
	return out
}
