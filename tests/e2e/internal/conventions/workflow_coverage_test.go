package conventions

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestWorkflowCoverage guards the execution wiring, not just the presence
// of test code: missing baselines and lost stability repetitions must fail.
func TestWorkflowCoverage(t *testing.T) {
	t.Parallel()
	root, err := env.RepoRoot()
	require.NoError(t, err)
	type step struct {
		ID   string
		Run  string
		If   string
		Uses string
		With map[string]string
		Env  map[string]string
	}
	type job struct {
		Name        string
		Permissions map[string]string
		Env         map[string]string
		Steps       []step
		Uses        string
		If          string
		Needs       yaml.Node
		Strategy    struct {
			Matrix struct {
				Shard    []int
				Workload []string
				Include  []struct{ Transport, Suite, Pkgs, Check string }
			}
		}
	}
	type workflow struct {
		Name string
		On   map[string]yaml.Node
		Env  map[string]string
		Jobs map[string]job
	}
	read := func(name string) workflow {
		data, err := os.ReadFile(filepath.Join(root, ".github", "workflows", name))
		require.NoError(t, err)
		var w workflow
		require.NoError(t, yaml.Unmarshal(data, &w))
		return w
	}
	t.Run("BidirectionalCompatibility", func(t *testing.T) {
		release := read("release.yml")
		verify := release.Jobs["verify"]
		require.Equal(t, "1", verify.Env["NYDUS_E2E_GOLDEN_REQUIRED"])
		require.Equal(t, "v3.0.0-beta.3", verify.Env["BASELINE_VERSION"])
		steps := make(map[string]string)
		for _, s := range verify.Steps {
			steps[s.ID] = s.Run
		}
		require.Contains(t, steps["generate-historical"], "$BASELINE_NYDUS")
		require.Contains(t, steps["read-historical"], "historical-golden")
		require.Contains(t, steps["generate-current"], "nydus-static/nydus")
		require.Contains(t, steps["read-current"], "generated-golden")
		require.Contains(t, steps["read-with-baseline"], `NYDUS_BIN="$BASELINE_NYDUS"`)
		require.Contains(t, steps["read-with-baseline"], "generated-golden")
		require.Contains(t, release.Jobs["verify-contract"].If, "github.event_name != 'pull_request'")
	})
	t.Run("UFFDStability", func(t *testing.T) {
		var found bool
		for _, s := range read("nightly.yml").Jobs["experimental"].Steps {
			if s.ID == "uffd-stability" {
				found = true
				require.Contains(t, s.Run, "E2E_COUNT=34")
				require.Contains(t, s.Run, "TestRealFault")
			}
		}
		require.True(t, found, "scheduled UFFD real faults must retain 34 repetitions")
	})
	t.Run("FUSEContinuity", func(t *testing.T) {
		var selections int
		for _, entry := range read("ci.yml").Jobs["e2e"].Strategy.Matrix.Include {
			for _, pkg := range strings.Fields(entry.Pkgs) {
				if pkg == "./continuity/..." {
					selections++
					require.Equal(t, "image-tools", entry.Suite)
				}
			}
		}
		require.Equal(t, 1, selections, "hot upgrade must run once in the image/services check")
	})
	t.Run("DragonflySchedule", func(t *testing.T) {
		dragonfly := read("e2e-dragonfly.yml")
		require.Contains(t, dragonfly.On, "schedule")
		require.Contains(t, dragonfly.On, "workflow_call")
		require.Equal(t, "./.github/workflows/e2e-dragonfly.yml", read("ci.yml").Jobs["e2e-dragonfly"].Uses)
		var setup string
		var uses []string
		for _, s := range dragonfly.Jobs["test"].Steps {
			setup += s.Run
			uses = append(uses, s.Uses)
		}
		require.Contains(t, uses, "helm/kind-action@v1")
		require.Contains(t, uses, "azure/setup-helm@v4")
		require.Contains(t, setup, "helm install --wait")
		require.Contains(t, setup, "registry:2")
		require.NotContains(t, setup, "cluster.sh")
		values, err := os.ReadFile(filepath.Join(root, "tests", "testdata", "charts", "config.yaml"))
		require.NoError(t, err)
		var chart map[string]struct {
			Enable bool
		}
		require.NoError(t, yaml.Unmarshal(values, &chart))
		require.False(t, chart["manager"].Enable)
		require.False(t, chart["client"].Enable)
		require.True(t, chart["seedClient"].Enable)

		require.Empty(t, dragonfly.Jobs["test"].Strategy.Matrix.Include)
		require.Equal(t, 1, strings.Count(setup, "make e2e-run PKG=./dragonfly/..."))
		require.NotContains(t, setup, "E2E_RUN=", "run every Dragonfly case without a filter")
	})
	t.Run("ConsolidatedRustAndUblk", func(t *testing.T) {
		ci := read("ci.yml")
		require.NotContains(t, ci.Jobs, "rust-privileged")
		require.NotContains(t, ci.Jobs, "feature-compat")
		require.NotContains(t, ci.Jobs, "ublk")
		rust := ci.Jobs["rust-test"]
		require.Equal(t, "1", rust.Env["NYDUS_TEST_REQUIRE_NETNS"])
		require.Equal(t, "1", rust.Env["NYDUS_TEST_REQUIRE_PTRACE"])
		var tests string
		for _, s := range rust.Steps {
			tests += s.Run
		}
		require.Contains(t, tests, "cargo llvm-cov --workspace")
		require.Contains(t, tests, "nydus/ublk")
		var setup string
		for _, s := range read("nightly.yml").Jobs["experimental"].Steps {
			setup += s.Run
		}
		require.Contains(t, setup, "modinfo ublk_drv")
		require.Contains(t, setup, `linux-modules-extra-$(uname -r)`)
		require.Contains(t, setup, "sudo modprobe ublk_drv")
	})
	t.Run("ProductCoverage", func(t *testing.T) {
		for file, testJobs := range map[string][]string{
			"ci.yml":            {"e2e"},
			"nightly.yml":       {"experimental", "soak", "fuzz"},
			"e2e-dragonfly.yml": {"test"},
		} {
			w := read(file)
			require.Len(t, w.Jobs, map[string]int{"ci.yml": 6, "nightly.yml": 4, "e2e-dragonfly.yml": 2}[file],
				"coverage must reuse existing jobs")
			require.Equal(t, "1", w.Env["CI_COVERAGE"], file)
			var build, paths string
			var llvmTools bool
			for _, s := range w.Jobs["build"].Steps {
				build += s.Run
				paths += s.With["path"]
				llvmTools = llvmTools || strings.Contains(s.With["components"], "llvm-tools-preview")
			}
			require.True(t, llvmTools, file)
			require.Contains(t, build, "e2e_coverage.sh bundle", file)
			require.Contains(t, paths, "coverage-tools/", file)
			for _, id := range testJobs {
				var export, artifact bool
				for _, s := range w.Jobs[id].Steps {
					if strings.Contains(s.Run, "e2e_coverage.sh export") {
						export = true
						require.Equal(t, "always()", s.If)
						require.Equal(t, "${{ steps.suites.outcome }}", s.Env["COVERAGE_TEST_OUTCOME"])
						if file == "ci.yml" {
							require.Contains(t, s.Run, "e2e_coverage.sh merge-go")
						}
					}
					if s.Uses == "actions/upload-artifact@v4" && s.With["path"] == "coverage/" {
						artifact = true
						require.Equal(t, "always()", s.If)
						require.Equal(t, "error", s.With["if-no-files-found"])
					}
					if s.Uses == "codecov/codecov-action@v5" {
						require.Contains(t, s.If, "github.event_name != 'pull_request'",
							"PR upload services must not consume test time budgets")
						require.NotEmpty(t, s.With["flags"])
						require.Equal(t, "true", s.With["disable_search"])
					}
				}
				require.True(t, export && artifact, "%s/%s coverage must export and survive failure", file, id)
			}
		}
		var rust string
		for _, s := range read("ci.yml").Jobs["rust-test"].Steps {
			rust += s.Run
		}
		require.Contains(t, rust, "cargo llvm-cov clean --workspace")
		require.Contains(t, rust, "cargo llvm-cov --no-report -p nydus-backend")
		require.Contains(t, rust, "--lib --")
		require.NotContains(t, rust, "--no-clean --no-report", "cargo-llvm-cov rejects this combination")
		require.Contains(t, rust, "cargo llvm-cov report --lcov")
		require.Contains(t, rust, "coverage/raw/rust")
		makefile, err := os.ReadFile(filepath.Join(root, "Makefile"))
		require.NoError(t, err)
		for _, option := range []string{"CI_COVERAGE ?= 0", "-coverpkg=./...", "-coverprofile=",
			"RUSTC_WORKSPACE_WRAPPER=", "CARGO_PROFILE_CI_STRIP=none", "LLVM_PROFILE_FILE=", "GOCOVERDIR=", "%8m.profraw"} {
			require.Contains(t, string(makefile), option)
		}
		require.NotContains(t, string(makefile), "%p.profraw", "fuzz subprocesses must use a bounded merge pool")
		require.NotContains(t, string(makefile), `RUSTFLAGS="$(RUSTFLAGS) -C instrument-coverage"`,
			"dependency instrumentation makes checksum-heavy E2E reads exceed the job budget")
		wrapper, err := os.ReadFile(filepath.Join(root, "tests/scripts/coverage_rustc.sh"))
		require.NoError(t, err)
		require.Contains(t, string(wrapper), `exec "$@" -C instrument-coverage`)
	})
	t.Run("CoverageGate", func(t *testing.T) {
		gate := read("ci.yml").Jobs["gate"]
		require.Equal(t, "always()", gate.If)
		var needs []string
		require.NoError(t, gate.Needs.Decode(&needs))
		require.ElementsMatch(t, []string{"rust-test", "e2e", "e2e-dragonfly", "extended"}, needs)
		require.Equal(t, map[string]string{"contents": "read", "actions": "read"}, gate.Permissions)
		var results, check bool
		for _, s := range gate.Steps {
			if strings.Contains(s.Run, `"$r" = success`) {
				results = true
				require.Contains(t, s.Run, "exit 1")
			}
			require.NotEqual(t, "actions/download-artifact@v4", s.Uses, "use the parser's newest-shard selection on reruns")
			if strings.Contains(s.Run, "--check-run") {
				require.True(t, results, "failed suites must block the gate before coverage")
				require.Equal(t, "python3 tests/scripts/coverage_comment.py --check-run", s.Run)
				require.Equal(t, "${{ github.run_id }}", s.Env["COVERAGE_RUN_ID"])
				require.Equal(t, "${{ github.token }}", s.Env["GH_TOKEN"])
				require.Empty(t, s.If)
				check = true
			}
		}
		require.True(t, results && check, "coverage must block the existing required check")
	})
	t.Run("CoverageComment", func(t *testing.T) {
		w := read("coverage-comment.yml")
		trigger := w.On["workflow_run"]
		var event struct{ Workflows, Types []string }
		require.NoError(t, trigger.Decode(&event))
		require.Equal(t, []string{"CI"}, event.Workflows)
		require.Equal(t, []string{"completed"}, event.Types)
		require.Len(t, w.Jobs, 1, "reporting must not add test shards")
		var checkout, reporter bool
		for _, s := range w.Jobs["report"].Steps {
			if s.Uses == "actions/checkout@v6" {
				checkout = true
				require.Equal(t, "${{ github.event.repository.default_branch }}", s.With["ref"],
					"privileged reporting must not execute PR code")
				require.Equal(t, "false", s.With["persist-credentials"])
			}
			if s.ID == "summary" {
				reporter = true
				require.Equal(t, "python3 tests/scripts/coverage_comment.py", s.Run)
				require.Equal(t, "${{ github.event.workflow_run.id }}", s.Env["COVERAGE_RUN_ID"])
			}
		}
		require.True(t, checkout && reporter)
	})
	t.Run("ExperimentalScope", func(t *testing.T) {
		extended := read("nightly.yml")
		for _, name := range []string{extended.Name, read("ci.yml").Jobs["extended"].Name} {
			require.NotEmpty(t, name)
			require.NotContains(t, strings.ToLower(name), "experimental",
				"the shared workflow also runs GA fuzz and stability tests")
		}
		for id, job := range extended.Jobs {
			if id != "experimental" {
				require.NotContains(t, strings.ToLower(job.Name), "experimental")
			}
		}
		want := []string{"nbd", "ublk", "fanotify", "uffd"}
		var transports []string
		for _, entry := range extended.Jobs["experimental"].Strategy.Matrix.Include {
			transports = append(transports, entry.Transport)
		}
		require.ElementsMatch(t, want, transports)
		entries, err := os.ReadDir(filepath.Join(root, "tests", "e2e", "experimental"))
		require.NoError(t, err)
		var suites []string
		for _, entry := range entries {
			if entry.IsDir() {
				suites = append(suites, entry.Name())
			}
		}
		require.ElementsMatch(t, want, suites)
	})
	t.Run("CheckNames", func(t *testing.T) {
		ci := read("ci.yml")
		require.Equal(t, "test / rust / unit-integration", ci.Jobs["rust-test"].Name)
		require.Equal(t, "build / binaries / ga", ci.Jobs["build"].Name)
		require.Equal(t, "gate / ci / required", ci.Jobs["gate"].Name)
		require.Equal(t, "test / ${{ matrix.check }}", ci.Jobs["e2e"].Name)
		require.Equal(t, "extended", ci.Jobs["extended"].Name)
		require.Equal(t, "distribution", ci.Jobs["e2e-dragonfly"].Name)
		require.Equal(t, "Classify PR", read("pr-labels.yml").Jobs["classify"].Name)

		label := regexp.MustCompile(`^[a-z0-9]+ / [a-z0-9]+ / [a-z0-9]+(?:-[a-z0-9]+)*$`)
		seen := make(map[string]bool)
		for _, entry := range ci.Jobs["e2e"].Strategy.Matrix.Include {
			name := "test / " + entry.Check
			require.Regexp(t, label, name)
			require.False(t, seen[name], "duplicate check name: %s", name)
			seen[name] = true
		}
	})
	t.Run("FuzzBudgets", func(t *testing.T) {
		fuzz := read("nightly.yml").Jobs["fuzz"]
		require.Empty(t, fuzz.Strategy.Matrix.Include)
		require.Empty(t, fuzz.Strategy.Matrix.Shard)
		for _, s := range fuzz.Steps {
			if strings.Contains(s.Run, "FuzzTarConversion") {
				require.Contains(t, s.Env["FUZZ_TIME"], "'150s' || '10m'")
				require.Contains(t, s.Run, "PKG=./tar/")
				require.Contains(t, s.Run, "PKG=./build/")
				require.Contains(t, s.Run, "FuzzBlobFormat")
				require.Equal(t, 2, strings.Count(s.Run, "E2E_PARALLEL=4"))
				require.Contains(t, s.Run, `wait "$tar_pid" || status=1`)
				require.Contains(t, s.Run, `wait "$blob_pid" || status=1`)
				require.Contains(t, s.Run, `exit "$status"`)
				return
			}
		}
		t.Fatal("missing combined fuzz command")
	})
	t.Run("LogicalGroups", func(t *testing.T) {
		ci := read("ci.yml")
		require.NotContains(t, ci.Jobs, "nydusify-test")
		groups := make(map[string][]string)
		for _, entry := range ci.Jobs["e2e"].Strategy.Matrix.Include {
			require.NotContains(t, groups, entry.Suite)
			groups[entry.Suite] = strings.Fields(entry.Pkgs)
		}
		want := map[string][]string{
			"image-tools":       {"./build/...", "./export/...", "./nydusify/...", "./kernel/...", "./tar/...", "./api/...", "./registry/...", "./continuity/..."},
			"fuse":              {"./contract/..."},
			"fileio-semantics":  {"./contract/..."},
			"fileio-data-zstd":  {"./contract/..."},
			"fileio-data-other": {"./contract/..."},
			"storage-recovery":  {"./fault/..."},
			"storage-cache":     {"./cache/...", "./soak/..."},
		}
		require.Equal(t, want, groups)
		var nydusifySteps int
		for _, s := range ci.Jobs["e2e"].Steps {
			if strings.Contains(s.Run, "make test-nydusify") {
				nydusifySteps++
				require.Contains(t, s.If, "matrix.suite == 'image-tools'")
				require.Contains(t, s.Run, "NYDUS_TEST_BUILDER=")
			}
		}
		require.Equal(t, 1, nydusifySteps)
		gate := ci.Jobs["gate"]
		var needs []string
		require.NoError(t, gate.Needs.Decode(&needs))
		require.ElementsMatch(t, []string{"rust-test", "e2e", "e2e-dragonfly", "extended"}, needs)

		soak := read("nightly.yml").Jobs["soak"]
		require.Empty(t, soak.Strategy.Matrix.Workload)
		var command string
		for _, s := range soak.Steps {
			command += s.Run
		}
		require.Contains(t, command, "^Test(Leak|Remote)$$")
		require.Contains(t, command, "E2E_PARALLEL=${{ github.event_name == 'pull_request' && 4 || 8 }}")

		lint := read("lint.yml")
		require.Len(t, lint.Jobs, 1)
		var checks string
		var modules []string
		for _, j := range lint.Jobs {
			for _, s := range j.Steps {
				checks += s.Run
				if strings.HasPrefix(s.Uses, "golangci/golangci-lint-action@") {
					modules = append(modules, s.With["working-directory"])
				}
			}
		}
		require.ElementsMatch(t, []string{"nydusify", "tests/e2e"}, modules)
		for _, check := range []string{"cargo fmt", "cargo clippy", "go test -count=1 ./internal/...",
			"go vet -tags manual ./manual/...", "go build -o /dev/null ./cmd/golden-gen"} {
			require.Contains(t, checks, check)
		}
		release := read("release.yml")
		require.NotContains(t, release.Jobs, "build-go")
		require.NotContains(t, release.Jobs, "build-rust")
		verify := release.Jobs["verify"]
		require.NoError(t, verify.Needs.Decode(&needs))
		require.Equal(t, []string{"build"}, needs)
		var build string
		for _, s := range release.Jobs["build"].Steps {
			build += s.Run
		}
		require.Contains(t, build, "cargo build -p nydus --release")
		require.Contains(t, build, "go build")
	})
}
