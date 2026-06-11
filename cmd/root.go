// Package cmd contains all CLI command definitions.
package cmd

import (
	"flag"
	"fmt"
	"os"
)

// GlobalFlags holds parsed values of flags shared across all subcommands.
type GlobalFlags struct {
	Kubeconfig string
	Context    string
	Namespace  string
	Output     string
	Pretty     bool
	Verbose    bool
	NoColor    bool
}

// Global is the parsed global flag set.
var Global GlobalFlags

// commandRegistry maps subcommand names to handler functions.
// Each cmd/*.go file registers itself via registerCommand() in init().
var commandRegistry = map[string]func([]string){}

func registerCommand(name string, fn func([]string)) {
	commandRegistry[name] = fn
}

func init() {
	// Register the scan command (defined in scan.go)
	registerCommand("scan", runScan)
}

// Execute is the entry point called by main().
func Execute() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}

	subcommand := os.Args[1]

	switch subcommand {
	case "-h", "--help", "help":
		printUsage()
		os.Exit(0)
	case "version":
		fmt.Printf("kubeaudit %s\n", Version)
		os.Exit(0)
	}

	handler, ok := commandRegistry[subcommand]
	if !ok {
		fmt.Fprintf(os.Stderr, "kubeaudit: unknown command %q\n\n", subcommand)
		printUsage()
		os.Exit(1)
	}

	handler(os.Args[2:])
}

const Version = "0.1.0-stage1"

// rootFS is kept for shared flag parsing if needed.
var _ = flag.NewFlagSet("kubeaudit", flag.ContinueOnError)

func printUsage() {
	fmt.Print(`kubeaudit — Kubernetes & Docker Security Auditor

Usage:
  kubeaudit <command> [flags]

Commands:
  scan      Scan a Kubernetes cluster for security findings
  docker    Scan running Docker containers for security findings
  version   Print version information
  help      Show this help

Kubernetes scan flags:
  --kubeconfig string   Path to kubeconfig (default: ~/.kube/config)
  --context    string   Kubernetes context (default: current-context)
  --namespace  string   Namespace to scan (default: all namespaces)
  --output     string   Output format: json (default: json)
  --pretty              Pretty-print JSON output
  --verbose             Print per-check timing
  --dry-run             Connect and fetch resources, skip checks

Docker scan flags:
  --socket  string      Docker socket path (default: /var/run/docker.sock)
  --timeout int         Scan timeout in seconds (default: 60)
  --workers int         Max parallel check workers (default: unlimited)
  --pretty              Pretty-print JSON output
  --verbose             Print per-check timing

Examples:
  kubeaudit scan
  kubeaudit scan --namespace production --pretty
  kubeaudit docker
  kubeaudit docker --pretty --verbose
  kubeaudit docker --socket /var/run/docker.sock | jq '.findings[] | select(.severity=="CRITICAL")'

`)
}
