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

func TestNewOptimizerPatternValidation(t *testing.T) {
	base := OptimizeOption{Source: "localhost:5000/src:v3", Target: "localhost:5000/dst:v3"}

	// Pattern missing.
	if _, err := NewOptimizer(base); err == nil ||
		!strings.Contains(err.Error(), "pattern must be provided") {
		t.Fatalf("expected missing-pattern error, got %v", err)
	}

	// Pattern provided.
	withPattern := base
	withPattern.Pattern = "/tmp/pattern.json"
	o, err := NewOptimizer(withPattern)
	if err != nil {
		t.Fatalf("pattern should be accepted: %v", err)
	}
	if o.opt.Pattern != "/tmp/pattern.json" {
		t.Fatalf("unexpected opt normalization: %+v", o.opt)
	}
}
