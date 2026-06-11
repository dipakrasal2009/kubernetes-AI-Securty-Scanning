package cmd

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/yourorg/kubeaudit/pkg/docker"
)

func init() {
	// Register "docker" as a top-level subcommand by adding it to the switch
	// in root.go — done via the registerCommand pattern below.
	registerCommand("docker", runDockerScan)
}

func runDockerScan(args []string) {
	fs := flag.NewFlagSet("docker", flag.ExitOnError)

	var (
		socketPath string
		timeout    int
		workers    int
		pretty     bool
		verbose    bool
	)

	fs.StringVar(&socketPath, "socket",  docker.DefaultSocket, "Docker Unix socket path")
	fs.IntVar(&timeout,       "timeout", 60,                   "Scan timeout in seconds")
	fs.IntVar(&workers,       "workers", 0,                    "Max parallel check workers (0 = unlimited)")
	fs.BoolVar(&pretty,       "pretty",  false,                "Pretty-print JSON output")
	fs.BoolVar(&verbose,      "verbose", false,                "Print per-check timing")

	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	result, err := docker.Scan(ctx, docker.ScanOptions{
		SocketPath: socketPath,
		Verbose:    verbose,
		MaxWorkers: workers,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: docker scan failed: %v\n\n", err)
		fmt.Fprintf(os.Stderr, "Is Docker running? Try:  docker info\n")
		fmt.Fprintf(os.Stderr, "Is the socket accessible? Try:  ls -la %s\n", socketPath)
		os.Exit(1)
	}

	// Output
	var data []byte
	if pretty {
		data, err = json.MarshalIndent(result, "", "  ")
	} else {
		data, err = json.Marshal(result)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshalling output: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))

	// CI exit code
	switch {
	case result.CountBySev["CRITICAL"] > 0:
		os.Exit(3)
	case result.CountBySev["HIGH"] > 0:
		os.Exit(2)
	case result.CountBySev["MEDIUM"] > 0 || result.CountBySev["LOW"] > 0:
		os.Exit(1)
	}
}
