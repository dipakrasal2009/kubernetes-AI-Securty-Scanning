package cmd

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/yourorg/kubeaudit/pkg/checks"
	"github.com/yourorg/kubeaudit/pkg/k8sclient"
	"github.com/yourorg/kubeaudit/pkg/models"
	"github.com/yourorg/kubeaudit/pkg/orchestrator"
	"github.com/yourorg/kubeaudit/pkg/reporter"
)

// scanFlags holds flags specific to the scan subcommand.
type scanFlags struct {
	timeout  int
	workers  int
	dryRun   bool
}

func runScan(args []string) {
	// ── 1. Parse scan-specific flags ─────────────────────────────────────────
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var sf scanFlags

	// Global flags re-declared here so they work in "kubeaudit scan --flag" order.
	fs.StringVar(&Global.Kubeconfig, "kubeconfig", Global.Kubeconfig, "Path to kubeconfig file")
	fs.StringVar(&Global.Context,    "context",    Global.Context,    "Kubernetes context")
	fs.StringVar(&Global.Namespace,  "namespace",  Global.Namespace,  "Namespace to scan")
	fs.StringVar(&Global.Output,     "output",     Global.Output,     "Output format")
	fs.BoolVar(&Global.Pretty,       "pretty",     Global.Pretty,     "Pretty-print JSON")
	fs.BoolVar(&Global.Verbose,      "verbose",    Global.Verbose,    "Verbose timing logs")

	fs.IntVar(&sf.timeout, "timeout", 60,    "Scan timeout in seconds")
	fs.IntVar(&sf.workers, "workers", 0,     "Max parallel check workers (0 = unlimited)")
	fs.BoolVar(&sf.dryRun, "dry-run", false, "Connect to cluster but skip checks; useful for testing auth")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	// ── 2. Connect to Kubernetes ──────────────────────────────────────────────
	if Global.Verbose {
		log.Printf("[scan] connecting to cluster  context=%q  namespace=%q",
			Global.Context, Global.Namespace)
	}

	client, err := k8sclient.NewClient(k8sclient.Config{
		KubeconfigPath: Global.Kubeconfig,
		Context:        Global.Context,
		Namespace:      Global.Namespace,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot connect to cluster: %v\n", err)
		os.Exit(1)
	}

	// ── 3. Fetch resources ────────────────────────────────────────────────────
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(sf.timeout)*time.Second)
	defer cancel()

	if Global.Verbose {
		log.Printf("[scan] fetching resources from %s", client.ServerURL())
	}

	resources, fetchErrs := client.FetchAll()
	for _, e := range fetchErrs {
		fmt.Fprintf(os.Stderr, "warning: %v\n", e)
	}

	totalChecked := len(resources.Deployments) +
		len(resources.Pods) +
		len(resources.Services) +
		len(resources.ClusterRoleBindings)

	if Global.Verbose {
		log.Printf("[scan] fetched  deployments=%d  pods=%d  services=%d  clusterrolebindings=%d",
			len(resources.Deployments),
			len(resources.Pods),
			len(resources.Services),
			len(resources.ClusterRoleBindings),
		)
	}

	if sf.dryRun {
		fmt.Fprintf(os.Stderr, "[dry-run] connection OK — %d resources found, skipping checks\n", totalChecked)
		os.Exit(0)
	}

	// ── 4. Build and run orchestrator ─────────────────────────────────────────
	orc := orchestrator.New(orchestrator.Options{
		MaxWorkers: sf.workers,
		Verbose:    Global.Verbose,
	})

	for _, c := range checks.DefaultChecks() {
		orc.Register(c)
	}

	if Global.Verbose {
		log.Printf("[scan] starting scan with %d checks", len(checks.DefaultChecks()))
	}

	start := time.Now()
	findings, err := orc.Run(ctx, resources)
	elapsed := time.Since(start)

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: scan failed: %v\n", err)
		os.Exit(1)
	}

	if Global.Verbose {
		log.Printf("[scan] completed  findings=%d  duration=%s", len(findings), elapsed.Round(time.Millisecond))
	}

	// ── 5. Build summary and report ───────────────────────────────────────────
	summary := models.BuildSummary(
		client.ServerURL(),
		client.Namespace(),
		totalChecked,
		findings,
	)

	switch Global.Output {
	case "json", "":
		r := reporter.NewJSONReporter(os.Stdout, Global.Pretty)
		if err := r.Report(summary); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: output format %q not yet supported (Stage 3)\n", Global.Output)
		os.Exit(1)
	}

	// ── 6. Exit code for CI gates ─────────────────────────────────────────────
	os.Exit(reporter.ExitCode(summary))
}
