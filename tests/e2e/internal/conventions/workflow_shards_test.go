package conventions

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/contract"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestWorkflowShards prevents a new layout, mode or own-mount case from
// silently falling outside the CI and shipped-binary contract partitions.
func TestWorkflowShards(t *testing.T) {
	t.Parallel()
	root, err := env.RepoRoot()
	require.NoError(t, err)
	var branches []string
	for _, adapter := range []struct {
		test string
		mount.Adapter
	}{
		{"TestFUSE", mount.FUSE{}},
		{"TestFileio", mount.Fileio{}},
	} {
		branches = append(branches, adapter.test+"/Semantic")
		for _, c := range contract.Cases() {
			if c.Scope == contract.Own &&
				(c.Supports == nil || c.Supports(adapter.Adapter, mount.Cold, fixture.Layout{})) {
				branches = append(branches, adapter.test+"/"+c.ID+"_"+c.Name)
			}
		}
		for _, layout := range fixture.Matrix {
			for _, mode := range mount.Modes {
				if !adapter.Supports(mode) || (mode == mount.Blob && strings.HasPrefix(layout, fixture.MergedPrefix)) {
					continue
				}
				branches = append(branches, adapter.test+"/Data/"+layout+"/"+string(mode))
			}
		}
	}
	for _, target := range []struct{ file, job string }{
		{"ci.yml", "e2e"},
		{"release.yml", "verify-contract"},
	} {
		t.Run(target.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, ".github", "workflows", target.file))
			require.NoError(t, err)
			var workflow struct {
				Jobs map[string]struct {
					Strategy struct {
						Matrix struct {
							Include []struct {
								Suite string
								Run   string
							}
						}
					}
				}
			}
			require.NoError(t, yaml.Unmarshal(data, &workflow))
			var selectors [][]*regexp.Regexp
			var names []string
			for _, shard := range workflow.Jobs[target.job].Strategy.Matrix.Include {
				if shard.Run == "" {
					continue
				}
				var selector []*regexp.Regexp
				// Make turns $$ into $; Go matches each slash-separated
				// component independently and runs all descendants.
				for _, part := range strings.Split(strings.ReplaceAll(shard.Run, "$$", "$"), "/") {
					re, err := regexp.Compile(part)
					require.NoError(t, err, "%s", shard.Suite)
					selector = append(selector, re)
				}
				selectors = append(selectors, selector)
				names = append(names, shard.Suite)
			}
			require.NotEmpty(t, selectors)
			hits := make([]int, len(selectors))
			for _, branch := range branches {
				parts := strings.Split(branch, "/")
				var selected []string
				for i, selector := range selectors {
					if len(selector) > len(parts) {
						continue
					}
					matches := true
					for j, re := range selector {
						if !re.MatchString(parts[j]) {
							matches = false
							break
						}
					}
					if matches {
						selected = append(selected, names[i])
						hits[i]++
					}
				}
				require.Len(t, selected, 1, "%s must run exactly once, selected by %v", branch, selected)
			}
			for i, hit := range hits {
				require.Positive(t, hit, "%s selects no contract branches", names[i])
			}
		})
	}
}
