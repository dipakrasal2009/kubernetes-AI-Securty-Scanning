// Package reporter contains output formatters.
// Stage 1 ships JSON. Stage 3 adds SARIF, HTML, and PDF.
package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/yourorg/kubeaudit/pkg/models"
)

// JSONReporter serialises a ScanSummary to JSON.
type JSONReporter struct {
	// Writer is where output is sent. Defaults to os.Stdout if nil.
	Writer io.Writer

	// Pretty enables indented JSON. Machine consumers should leave this false.
	Pretty bool
}

// NewJSONReporter creates a JSONReporter that writes to w.
// Pass nil to write to stdout.
func NewJSONReporter(w io.Writer, pretty bool) *JSONReporter {
	if w == nil {
		w = os.Stdout
	}
	return &JSONReporter{Writer: w, Pretty: pretty}
}

// Report writes the ScanSummary as JSON to the configured Writer.
func (r *JSONReporter) Report(summary models.ScanSummary) error {
	var (
		data []byte
		err  error
	)
	if r.Pretty {
		data, err = json.MarshalIndent(summary, "", "  ")
	} else {
		data, err = json.Marshal(summary)
	}
	if err != nil {
		return fmt.Errorf("marshalling report: %w", err)
	}

	data = append(data, '\n')
	if _, err := r.Writer.Write(data); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}
	return nil
}

// ExitCode returns the process exit code appropriate for the scan result:
//
//	0 — no findings
//	1 — LOW or MEDIUM findings only
//	2 — HIGH findings present
//	3 — CRITICAL findings present
//
// CI pipelines use this to gate deployments.
func ExitCode(summary models.ScanSummary) int {
	if summary.CountBySev["CRITICAL"] > 0 {
		return 3
	}
	if summary.CountBySev["HIGH"] > 0 {
		return 2
	}
	if summary.CountBySev["MEDIUM"] > 0 || summary.CountBySev["LOW"] > 0 {
		return 1
	}
	return 0
}
