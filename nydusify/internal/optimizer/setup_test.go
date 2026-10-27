/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package optimizer

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOptimizerSetupFailures(t *testing.T) {
	for _, opt := range []OptimizeOption{{}, {Source: "source"}} {
		_, err := NewOptimizer(opt)
		require.Error(t, err)
	}
	for _, phase := range []string{"content", "scratch"} {
		t.Run(phase, func(t *testing.T) {
			work := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(work, phase), nil, 0o600))
			opt, err := NewOptimizer(OptimizeOption{Source: "://invalid", Target: "target", TraceFile: "trace", WorkDir: work})
			require.NoError(t, err)
			require.ErrorContains(t, opt.Optimize(context.Background()), "create dir")
		})
	}
}
