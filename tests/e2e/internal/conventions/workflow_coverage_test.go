package conventions

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
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
		ID              string
		Name            string
		Run             string
		If              string
		Uses            string
		ContinueOnError string `yaml:"continue-on-error"`
		With            map[string]string
		Env             map[string]string
	}
	type job struct {
		Name        string
		Permissions map[string]string
		Env         map[string]string
		Steps       []step
		Uses        string
		With        map[string]string
		If          string
		Needs       yaml.Node
		Strategy    struct {
			Matrix struct {
				Shard     []int
				Workload  []string
				Transport []string
				Include   []struct {
					Suite, Pkgs  string
					SoakDuration string `yaml:"soak-duration"`
				}
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
		compatibility := read("e2e-compatibility.yml")
		for _, event := range []string{"push", "pull_request", "schedule"} {
			require.Contains(t, compatibility.On, event)
		}
		var run string
		for _, s := range compatibility.Jobs["test"].Steps {
			run += s.Run
		}
		require.Contains(t, run, "make e2e-compatibility", "the compatibility flow lives in the Makefile, the workflow only runs it")
		makefile, err := os.ReadFile(filepath.Join(root, "Makefile"))
		require.NoError(t, err)
		recipe := string(makefile)[strings.Index(string(makefile), "e2e-compatibility:"):]
		recipe = recipe[:strings.Index(recipe, ".PHONY: e2e-compatibility")]
		require.Contains(t, string(makefile), "BASELINE_VERSION ?= v3.0.0-beta.3")
		require.Contains(t, recipe, "sha256sum -c", "the baseline download is checksum-verified")
		require.Contains(t, recipe, "-nydus $(BASELINE_NYDUS) -out $(GOLDEN_DIR)/historical")
		require.Contains(t, recipe, "-nydus $(NYDUS_BIN) -out $(GOLDEN_DIR)/current")
		require.Contains(t, recipe, "NYDUS_E2E_GOLDEN_DIR=$(GOLDEN_DIR)/historical NYDUS_E2E_GOLDEN_VERSIONS=$(BASELINE_VERSION)")
		require.Contains(t, recipe, "E2E_RUN='^(TestRead|TestGAFeatures)$$$$'")
		require.Contains(t, recipe, "E2E_RUN='^TestRead$$$$/[^/]+/[^/]+/^(Check|FUSE|Export)$$$$' E2E_TIMEOUT=2m NYDUS_BIN=$(BASELINE_NYDUS)")
		release := read("release.yml")
		require.ElementsMatch(t, []string{"build", "release"}, slices.Collect(maps.Keys(release.Jobs)), "release builds, packages and publishes; tests live in e2e workflows")
	})
	t.Run("UFFDStability", func(t *testing.T) {
		var found bool
		for _, s := range read("e2e-experimental.yml").Jobs["test"].Steps {
			if s.Name == "Run UFFD stability test" {
				found = true
				require.Contains(t, s.Run, "E2E_COUNT=34")
				require.Contains(t, s.Run, "TestRealFault")
			}
		}
		require.True(t, found, "scheduled UFFD real faults must retain 34 repetitions")
	})
	t.Run("FUSEContinuity", func(t *testing.T) {
		var selections int
		for _, entry := range read("e2e.yml").Jobs["e2e"].Strategy.Matrix.Include {
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
		for _, event := range []string{"push", "pull_request", "schedule"} {
			require.Contains(t, dragonfly.On, event)
		}
		require.NotContains(t, dragonfly.On, "workflow_call", "test workflows trigger on their own, ci.yml runs only unit tests")
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
		rust := ci.Jobs["test"]
		var tests string
		for _, s := range rust.Steps {
			tests += s.Run
		}
		require.Contains(t, tests, "cargo llvm-cov --workspace")
		require.Contains(t, tests, "nydus/ublk")
		var setup string
		for _, s := range read("e2e-experimental.yml").Jobs["test"].Steps {
			setup += s.Run
		}
		require.Contains(t, setup, "modinfo ublk_drv")
		require.Contains(t, setup, `linux-modules-extra-$(uname -r)`)
		require.Contains(t, setup, "sudo modprobe ublk_drv")
	})
	t.Run("ProductCoverage", func(t *testing.T) {
		for file, testJobs := range map[string][]string{
			"e2e.yml":               {"e2e"},
			"e2e-experimental.yml":  {"test"},
			"e2e-dragonfly.yml":     {"test"},
			"e2e-compatibility.yml": {"test"},
			"fuzz.yml":              {"fuzz"},
		} {
			w := read(file)
			require.Len(t, w.Jobs, map[string]int{"e2e.yml": 2, "e2e-experimental.yml": 2, "e2e-dragonfly.yml": 1, "e2e-compatibility.yml": 1, "fuzz.yml": 1}[file],
				"coverage must reuse existing jobs")
			require.NotContains(t, w.Env, "COVERAGE", "coverage is the build-coverage target, not an env knob")
			for _, id := range testJobs {
				var build, paths string
				var llvmTools bool
				for _, s := range append(w.Jobs["build"].Steps, w.Jobs[id].Steps...) {
					build += s.Run
					paths += s.With["path"]
					llvmTools = llvmTools || strings.Contains(s.With["components"], "llvm-tools-preview")
				}
				require.True(t, llvmTools, file)
				require.Contains(t, build, "make build-coverage", file)
				if _, shared := w.Jobs["build"]; shared {
					require.Contains(t, paths, "coverage-tools/", file)
				}
				var export, upload bool
				for _, s := range w.Jobs[id].Steps {
					if strings.Contains(s.Run, "e2e_coverage.sh export") {
						export = true
						require.Empty(t, s.If, "coverage is exported and uploaded only after the tests pass, as in dragonfly")
					}
					if s.Uses == "codecov/codecov-action@v5" {
						upload = true
						require.Contains(t, s.With["files"], "coverage/rust-e2e.lcov")
						require.Contains(t, []string{"e2etests", "fuzz"}, s.With["flags"])
						require.Equal(t, "true", s.With["disable_search"])
						require.Equal(t, "true", s.ContinueOnError, "upload services must not fail tests")
					}
				}
				require.True(t, export && upload, "%s/%s coverage must export and upload", file, id)
			}
		}
		var rust string
		for _, s := range read("ci.yml").Jobs["test"].Steps {
			rust += s.Run
		}
		require.Contains(t, rust, "cargo llvm-cov clean --workspace")
		require.Contains(t, rust, "cargo llvm-cov --no-report -p nydus-backend")
		require.Contains(t, rust, "--lib --")
		require.NotContains(t, rust, "--no-clean --no-report", "cargo-llvm-cov rejects this combination")
		require.Contains(t, rust, "cargo llvm-cov report --lcov")
		makefile, err := os.ReadFile(filepath.Join(root, "Makefile"))
		require.NoError(t, err)
		for _, option := range []string{"build-coverage: COVERAGE = 1", "COVERAGE ?= $(if $(wildcard $(COVERAGE_TOOLS_DIR)/binaries.sha256),1,0)", "-coverpkg=./...", "-coverprofile=",
			"RUSTC_WORKSPACE_WRAPPER=", "CARGO_PROFILE_CI_STRIP=none", "LLVM_PROFILE_FILE=", "GOCOVERDIR=", "%8m.profraw"} {
			require.Contains(t, string(makefile), option)
		}
		require.NotContains(t, string(makefile), "E2E_REQUIRE", "CI is the only strictness switch")
		for _, f := range []string{"ci.yml", "e2e.yml", "e2e-dragonfly.yml", "e2e-experimental.yml", "e2e-compatibility.yml", "fuzz.yml", "release.yml"} {
			data, err := os.ReadFile(filepath.Join(root, ".github", "workflows", f))
			require.NoError(t, err)
			for _, knob := range []string{"E2E_REQUIRE", "NYDUS_TEST_FAIL_KNOWN_ISSUES", "NYDUS_TEST_REQUIRE_", "NYDUS_E2E_GOLDEN_REQUIRED"} {
				require.NotContains(t, string(data), knob, "%s: GitHub Actions sets CI=true", f)
			}
		}
		require.NotContains(t, string(makefile), "%p.profraw", "fuzz subprocesses must use a bounded merge pool")
		require.NotContains(t, string(makefile), `RUSTFLAGS="$(RUSTFLAGS) -C instrument-coverage"`,
			"dependency instrumentation makes checksum-heavy E2E reads exceed the job budget")
		wrapper, err := os.ReadFile(filepath.Join(root, "tests/scripts/coverage_rustc.sh"))
		require.NoError(t, err)
		require.Contains(t, string(wrapper), `exec "$@" -C instrument-coverage`)
	})
	t.Run("CoverageGate", func(t *testing.T) {
		ci := read("ci.yml")
		require.ElementsMatch(t, []string{"test", "test-nydusify"}, slices.Collect(maps.Keys(ci.Jobs)),
			"ci.yml runs unit tests only; e2e, fuzz and variants have their own workflows")
		for id, j := range ci.Jobs {
			require.Empty(t, j.Uses)
			var upload bool
			for _, s := range j.Steps {
				if s.Uses == "codecov/codecov-action@v5" {
					upload = true
					require.Equal(t, "unittests", s.With["flags"], id)
				}
			}
			require.True(t, upload, "%s must upload to Codecov, which merges flags and gates the commit", id)
		}
		var nydusify string
		for _, s := range ci.Jobs["test-nydusify"].Steps {
			nydusify += s.Run
		}
		require.Contains(t, nydusify, "make test-nydusify")
		entries, err := os.ReadDir(filepath.Join(root, ".github", "workflows"))
		require.NoError(t, err)
		for _, entry := range entries {
			require.NotEqual(t, "coverage.yml", entry.Name(), "Codecov owns merging, commenting and the threshold")
		}
		codecov, err := os.ReadFile(filepath.Join(root, "codecov.yml"))
		require.NoError(t, err)
		require.Equal(t, 2, strings.Count(string(codecov), "target: 90%"), "Rust and Go are gated separately")
	})
	t.Run("ExperimentalScope", func(t *testing.T) {
		experimental := read("e2e-experimental.yml")
		require.Equal(t, "E2E Test With Experimental Transports", experimental.Name)
		for _, file := range []string{"fuzz.yml", "e2e-nightly.yml"} {
			require.NotContains(t, strings.ToLower(read(file).Name), "experimental",
				"fuzz and stability soaks validate GA behavior")
		}
		want := []string{"nbd", "ublk", "fanotify", "uffd"}
		require.ElementsMatch(t, want, experimental.Jobs["test"].Strategy.Matrix.Transport)
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
		ci, e2e := read("ci.yml"), read("e2e.yml")
		require.Equal(t, "Test", ci.Jobs["test"].Name)
		require.Equal(t, "Test Nydusify", ci.Jobs["test-nydusify"].Name)
		require.Equal(t, "Build", e2e.Jobs["build"].Name)
		require.Equal(t, "e2e (${{ matrix.suite }})", e2e.Jobs["e2e"].Name, "include rows carry pkgs and knobs, so the name is set to the suite alone")
		require.Equal(t, "Fuzz", read("fuzz.yml").Jobs["fuzz"].Name)
		require.Equal(t, "Classify PR", read("pr-labels.yml").Jobs["classify"].Name)

		seen := make(map[string]bool)
		for _, entry := range e2e.Jobs["e2e"].Strategy.Matrix.Include {
			require.False(t, seen[entry.Suite], "duplicate suite: %s", entry.Suite)
			seen[entry.Suite] = true
		}
	})
	t.Run("FuzzBudgets", func(t *testing.T) {
		fuzz := read("fuzz.yml").Jobs["fuzz"]
		require.Empty(t, fuzz.Strategy.Matrix.Include)
		require.Empty(t, fuzz.Strategy.Matrix.Shard)
		for _, s := range fuzz.Steps {
			if strings.Contains(s.Run, "FuzzTarConversion") {
				require.Equal(t, "${{ github.event_name == 'schedule' && '10m' || '150s' }}", s.Env["FUZZ_TIME"], "PRs fuzz each target for 150 seconds")
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
		ci, e2e := read("ci.yml"), read("e2e.yml")
		groups := make(map[string][]string)
		for _, entry := range e2e.Jobs["e2e"].Strategy.Matrix.Include {
			require.NotContains(t, groups, entry.Suite)
			groups[entry.Suite] = strings.Fields(entry.Pkgs)
		}
		want := map[string][]string{
			"image-tools":       {"./internal/...", "./build/...", "./export/...", "./nydusify/...", "./kernel/...", "./tar/...", "./api/...", "./registry/...", "./continuity/..."},
			"fuse":              {"./contract/..."},
			"fileio-semantics":  {"./contract/..."},
			"fileio-data-zstd":  {"./contract/..."},
			"fileio-data-other": {"./contract/..."},
			"storage-recovery":  {"./fault/..."},
			"storage-cache":     {"./cache/..."},
			"soak":              {"./soak/..."},
		}
		require.Equal(t, want, groups)
		for _, s := range e2e.Jobs["e2e"].Steps {
			require.NotContains(t, s.Run, "make test-nydusify", "nydusify unit tests belong to ci.yml")
		}
		require.Contains(t, ci.Jobs, "test-nydusify")
		for _, entry := range e2e.Jobs["e2e"].Strategy.Matrix.Include {
			if entry.Suite == "soak" {
				require.Equal(t, "2m", entry.SoakDuration, "PRs soak each leaf for two minutes")
			} else {
				require.Empty(t, entry.SoakDuration)
			}
		}
		nightly := read("e2e-nightly.yml")
		require.Contains(t, nightly.On, "schedule")
		require.ElementsMatch(t, []string{"soak", "hugetar"}, slices.Collect(maps.Keys(nightly.Jobs)))
		var command string
		for _, s := range nightly.Jobs["soak"].Steps {
			command += s.Run
		}
		require.Contains(t, command, "make e2e-soak")
		require.NotContains(t, command, "SOAK_DURATION=", "the nightly soak keeps the Makefile's one-hour default")
		require.Contains(t, command, "E2E_PARALLEL=4", "all four local/remote x FUSE/Fileio leaves run in one wave")

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
		for _, check := range []string{"cargo fmt", "cargo clippy",
			"go vet -tags manual ./manual/...", "go build -o /dev/null ./cmd/golden-gen"} {
			require.Contains(t, checks, check)
		}
		require.NotContains(t, checks, "go test", "harness unit tests run with the e2e module, not as a lint")
		release := read("release.yml")
		var build string
		for _, s := range release.Jobs["build"].Steps {
			build += s.Run
		}
		require.Contains(t, build, "cargo build -p nydus --release")
		require.Contains(t, build, "go build")
	})
}
