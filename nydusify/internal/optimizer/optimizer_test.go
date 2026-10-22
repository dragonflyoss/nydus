/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package optimizer

import (
	"strings"
	"testing"
)

func TestNewOptimizerTraceFileValidation(t *testing.T) {
	base := OptimizeOption{Source: "localhost:5000/src:v3", Target: "localhost:5000/dst:v3"}

	// Trace file missing.
	if _, err := NewOptimizer(base); err == nil ||
		!strings.Contains(err.Error(), "trace file must be provided") {
		t.Fatalf("expected missing-trace-file error, got %v", err)
	}

	// Trace file provided.
	withTraceFile := base
	withTraceFile.TraceFile = "/tmp/trace.json"
	o, err := NewOptimizer(withTraceFile)
	if err != nil {
		t.Fatalf("trace file should be accepted: %v", err)
	}
	if o.opt.TraceFile != "/tmp/trace.json" {
		t.Fatalf("unexpected opt normalization: %+v", o.opt)
	}
}
