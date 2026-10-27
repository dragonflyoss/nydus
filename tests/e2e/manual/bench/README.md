# Stable-host performance regression checks

The benchmark reports by default. No machine-independent latency or
throughput threshold is imposed. Use a dedicated idle host and explicitly
select modes (`NYDUSFS_BENCH_MODES=fuse,fileio`); a requested missing or
unknown mode now fails through the normal precondition policy rather than
silently producing a reduced table.

Set `NYDUSFS_BENCH_OUTPUT` to save JSON and `NYDUSFS_BENCH_HOST` to a stable
host identity. Repeated runs should establish variance before choosing a
budget. Preserve an accepted report outside the checkout as a baseline.
To gate a later run, set:

* `NYDUSFS_BENCH_BASELINE`: path to that accepted JSON report;
* `NYDUSFS_BENCH_MAX_REGRESSION_PERCENT`: explicit finite percentage in
  `(0,100]`, calibrated to the host's measured variance.

Both settings are required together. Baselines must have identical host,
architecture, kernel, mode/metric sets and workload environment settings.
Missing, zero, or nonfinite metrics are errors, not improvements. Latency
increases and throughput decreases are compared in their correct direction.
The manual workflow maps `E2E_BENCH_*` repository variables to these knobs
and uploads `bench-results.json` even on a regression. Keep baseline paths
on the dedicated runner; do not auto-update a baseline from the candidate.

The new `big_dir_lookup_ops` metric is a single positive-lookup pass over
the `small/` directory (10,000 entries by default) on a **fresh mount**,
without readdir or a preceding metadata walk. It complements the existing
negative-dentry rate and detects large-directory lookup regressions instead
of measuring repeated warm dcache hits. `NYDUSFS_PERF_SMALL_FILE_COUNT`
changes its size. Cold mount, metadata/xattr walk, first read, sequential
and random read metrics also participate in the optional gate.

`go test ./internal/benchgate -run TestBaseline` validates comparison
direction, host/workload matching, and invalid budgets without running fio.
`make test-bench` builds GA features only. Optional experimental columns
require an explicitly built binary and a capability-matched host. The manual
workflow's `E2E_BENCH_FEATURES` can opt into those features, paired with
`E2E_BENCH_MODES` and matching runner labels; ublk is not an incidental
dependency of a GA performance run.
