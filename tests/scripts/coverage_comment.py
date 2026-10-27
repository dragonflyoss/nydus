#!/usr/bin/env python3
"""Merge CI report data and update one PR comment; never execute PR artifacts."""

import argparse
import io
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import urlencode
import zipfile


EXPECTED = {
    "coverage-rust-unit-integration",
    *(f"coverage-e2e-{s}" for s in (
        "image-tools", "fuse", "fileio-semantics", "fileio-data-zstd",
        "fileio-data-other", "storage-recovery", "storage-cache",
    )),
    *(f"coverage-experimental-{s}" for s in ("nbd", "fanotify", "uffd", "ublk")),
    "coverage-soak", "coverage-fuzz", "coverage-dragonfly",
}
REPORTS = {
    "status.txt", "rust-unit-integration.lcov", "rust-e2e.lcov",
    "go-unit-integration.out", "go-e2e.out",
}
MAX_ZIP = 64 * 1024 * 1024
MAX_REPORT = 16 * 1024 * 1024
MARKER = "<!-- nydus-coverage:v1 "


def gh(path, *, payload=None, pages=False):
    args = ["gh", "api", path]
    if pages:
        args += ["--paginate", "--slurp"]
    if payload is not None:
        args += ["--method", "PATCH" if "/issues/comments/" in path else "POST", "--input", "-"]
    result = subprocess.run(
        args, input=json.dumps(payload).encode() if payload is not None else None,
        stdout=subprocess.PIPE, check=True, timeout=90,
    )
    return json.loads(result.stdout)


def reports_from_zip(data):
    if len(data) > MAX_ZIP:
        raise ValueError("artifact exceeds compressed size limit")
    result = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        if len(archive.infolist()) > 10000:
            raise ValueError("artifact has too many entries")
        for entry in archive.infolist():
            if entry.filename not in REPORTS:
                continue
            if entry.filename in result or entry.file_size > MAX_REPORT:
                raise ValueError("duplicate or oversized report")
            with archive.open(entry) as stream:
                content = stream.read(MAX_REPORT + 1)
            if len(content) > MAX_REPORT:
                raise ValueError("report exceeds decompressed size limit")
            result[entry.filename] = content.decode("utf-8")
    return result


def latest_artifacts(artifacts):
    result = {}
    # Failed-job reruns retain older artifacts with the same name.
    for artifact in sorted(artifacts, key=lambda item: (item["created_at"], item["id"])):
        if artifact["name"] in EXPECTED:
            result[artifact["name"]] = artifact
    return result


def download_reports(repo, run_id):
    artifacts = gh(f"repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100")
    if artifacts["total_count"] > 100:
        raise ValueError("too many artifacts")
    shards = {}
    for artifact in latest_artifacts(artifacts["artifacts"]).values():
        if artifact["expired"]:
            continue
        if artifact["size_in_bytes"] > MAX_ZIP:
            raise ValueError("oversized coverage artifact")
        data = subprocess.run(
            ["gh", "api", f'repos/{repo}/actions/artifacts/{int(artifact["id"])}/zip'],
            stdout=subprocess.PIPE, check=True, timeout=90,
        ).stdout
        shards[artifact["name"]] = reports_from_zip(data)
    return shards


def rust_lines(text):
    result = {}
    source = None
    for line in text.splitlines():
        if line.startswith("SF:"):
            match = re.search(r"(?:^|/)(nydus(?:-[a-z0-9]+)?/(?:src|tests)/[A-Za-z0-9_./-]+\.rs)$", line[3:])
            source = match[1] if match else None
            if source and ".." in source.split("/"):
                raise ValueError("invalid Rust source path")
        elif line.startswith("DA:") and source:
            fields = line[3:].split(",")
            if len(fields) not in (2, 3) or not all(v.isdecimal() for v in fields[:2]):
                raise ValueError("invalid Rust line counter")
            number, count = map(int, fields[:2])
            if number < 1:
                raise ValueError("invalid Rust source line")
            key = (source, number)
            result[key] = result.get(key, False) or count > 0
        elif line == "end_of_record":
            source = None
    if not result:
        raise ValueError("empty workspace Rust report")
    return result


def go_blocks(text):
    lines = text.splitlines()
    if not lines or lines[0] not in ("mode: set", "mode: count", "mode: atomic"):
        raise ValueError("invalid Go coverage header")
    result = {}
    for line in lines[1:]:
        match = re.fullmatch(
            r"(github\.com/dragonflyoss/nydus/nydusify/[A-Za-z0-9_./-]+\.go:"
            r"[1-9][0-9]*\.[1-9][0-9]*,[1-9][0-9]*\.[1-9][0-9]*) ([0-9]+) ([0-9]+)", line,
        )
        if not match or ".." in match[1].split("/"):
            raise ValueError("invalid Go coverage block")
        location, statements, count = match.groups()
        statements = int(statements)
        previous = result.get(location, (statements, False))
        if previous[0] != statements:
            raise ValueError("incompatible Go statement counts")
        result[location] = (statements, previous[1] or int(count) > 0)
    if not result:
        raise ValueError("empty Go report")
    return result


def merge_go(target, incoming):
    def layouts(blocks):
        result = {}
        for location, (count, _) in blocks.items():
            result.setdefault(location.rsplit(":", 1)[0], set()).add((location, count))
        return result

    old, new = layouts(target), layouts(incoming)
    if any(old[source] != layout for source, layout in new.items() if source in old):
        raise ValueError("incompatible Go source blocks")
    for location, (count, hit) in incoming.items():
        target[location] = (count, hit or target.get(location, (count, False))[1])


def merge_reports(shards):
    rust, go, problems = {}, {}, []
    for name in sorted(EXPECTED):
        reports = shards.get(name)
        if reports is None:
            problems.append(f"{name}: missing or expired artifact")
            continue
        status = dict(line.split("=", 1) for line in reports.get("status.txt", "").splitlines() if "=" in line)
        if status.get("test_outcome") != "success" or status.get("dual_tls_outcome", "success") != "success":
            problems.append(f"{name}: tests failed, cancelled, or have no successful status")
        if status.get("collection") in ("export-failed", "not-run-or-cancelled"):
            problems.append(f"{name}: incomplete export")
        required = {"rust-unit-integration.lcov" if name == "coverage-rust-unit-integration" else "rust-e2e.lcov"}
        if name == "coverage-e2e-image-tools":
            required |= {"go-unit-integration.out", "go-e2e.out"}
        if required - reports.keys():
            problems.append(f"{name}: missing report")
        next_rust, next_go = rust.copy(), go.copy()
        try:
            for filename, text in reports.items():
                if filename.endswith(".lcov"):
                    for key, hit in rust_lines(text).items():
                        next_rust[key] = next_rust.get(key, False) or hit
                elif filename.endswith(".out"):
                    merge_go(next_go, go_blocks(text))
        except ValueError as error:
            problems.append(f"{name}: invalid report ({error})")
            continue
        rust, go = next_rust, next_go
    return rust, go, problems


def fraction(covered, total):
    return f"{covered:,} / {total:,} ({covered / total:.2%})" if total else "No usable report"


def coverage_totals(rust, go):
    return {
        "Rust lines": (sum(rust.values()), len(rust)),
        "Go statements": (sum(n for n, hit in go.values() if hit), sum(n for n, _ in go.values())),
    }


def threshold_failures(rust, go):
    return [f"{language}: {fraction(covered, total)}; minimum is 90%"
            for language, (covered, total) in coverage_totals(rust, go).items()
            if not total or covered * 100 < total * 90]


def check_directory(directory):
    shards = {}
    for name in EXPECTED:
        shard = directory / name
        if not shard.is_dir():
            continue
        shards[name] = {}
        for filename in REPORTS:
            path = shard / filename
            if path.is_file():
                with path.open("rb") as stream:
                    data = stream.read(MAX_REPORT + 1)
                if len(data) > MAX_REPORT:
                    raise ValueError("oversized coverage report")
                shards[name][filename] = data.decode("utf-8")
    return check_reports(shards)


def check_reports(shards):
    rust, go, problems = merge_reports(shards)
    problems += threshold_failures(rust, go)
    summary = ["## Coverage gate (minimum 90% each)", "", "| Metric | Coverage |", "| --- | --- |"]
    summary += [f"| {language} | {fraction(*counts)} |" for language, counts in coverage_totals(rust, go).items()]
    summary += [""] + [f"- {problem}" for problem in problems]
    text = "\n".join(summary) + "\n"
    print(text)
    if "GITHUB_STEP_SUMMARY" in os.environ:
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
            stream.write(text)
    return 1 if problems else 0


def comment(run, rust, go, problems):
    sha = run["head_sha"]
    body = [
        f'{MARKER}run={run["id"]} attempt={run["run_attempt"]} sha={sha} -->',
        "### CI coverage",
        f'Commit `{sha[:12]}` · [CI run]({run["html_url"]}) · **{run["conclusion"]}**',
        "",
        "| Language | Coverage union across available checks |",
        "| --- | --- |",
        f"| Rust lines | {fraction(sum(rust.values()), len(rust))} |",
        f"| Go statements | {fraction(sum(n for n, hit in go.values() if hit), sum(n for n, _ in go.values()))} |",
        "",
        "**Partial results** — do not interpret missing shards as zero coverage."
        if problems else "All expected shards and reports are present with successful test statuses.",
        "Hits are deduplicated, not percentages added together. Rust includes test "
        "code; this is not production-only or branch coverage. Go measures nydusify, not the E2E harness. "
        "Killed/aborted processes may not flush counters, so subprocess coverage is a lower bound.",
        "No baseline delta is claimed without a comparable base-commit report.",
    ]
    if problems:
        body += ["", "<details><summary>Missing or incomplete coverage</summary>", ""]
        body += [f"- {problem}" for problem in problems]
        body += ["", "</details>"]
    body += ["", f'Raw profiles, individual reports and status files: [CI artifacts]({run["html_url"]}#artifacts).']
    return "\n".join(body) + "\n"


def matching_pr(pr, run, repo):
    return (pr["state"] == "open" and pr["base"]["repo"]["full_name"] == repo
            and pr["head"]["repo"] is not None
            and pr["head"]["repo"]["full_name"] == run["head_repository"]["full_name"]
            and pr["head"]["sha"] == run["head_sha"])


def newer_comment(body, run):
    match = re.match(re.escape(MARKER) + r"run=(\d+) attempt=(\d+) sha=([a-f0-9]{40}) -->", body)
    if not match:
        raise ValueError("invalid existing coverage comment marker")
    return (int(match[1]), int(match[2])) > (run["id"], run["run_attempt"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--check-dir", type=Path, help="enforce 90%% for each language using downloaded CI shards")
    parser.add_argument("--check-run", action="store_true", help="enforce 90%% using the latest shards of this CI run")
    args = parser.parse_args()
    if args.check_dir is not None:
        raise SystemExit(check_directory(args.check_dir))
    repo = os.environ["GITHUB_REPOSITORY"]
    run_id = int(os.environ["COVERAGE_RUN_ID"])
    if args.check_run:
        raise SystemExit(check_reports(download_reports(repo, run_id)))
    run = gh(f"repos/{repo}/actions/runs/{run_id}")
    if (run["path"] != ".github/workflows/ci.yml" or run["status"] != "completed"
            or run["event"] not in ("pull_request", "push")
            or not re.fullmatch("[a-f0-9]{40}", run["head_sha"])):
        raise ValueError("not a completed supported CI run")
    prs = []
    if run["event"] == "pull_request":
        query = urlencode({"state": "open", "head": run["head_repository"]["full_name"].split("/")[0]
                           + ":" + run["head_branch"], "per_page": 100})
        candidates = gh(f"repos/{repo}/pulls?{query}")
        prs = [pr for pr in candidates if matching_pr(pr, run, repo)]
        if len(prs) > 1:
            raise ValueError("ambiguous PR identity for this run")
        if not prs:
            print("No open PR still has this run's head; leaving comments unchanged.")
            return
    rust, go, problems = merge_reports(download_reports(repo, run_id))
    if run["conclusion"] != "success":
        problems.append("CI did not succeed; artifacts alone do not establish a successful full run")
    body = comment(run, rust, go, problems)
    output = Path("coverage-summary")
    output.mkdir(exist_ok=True)
    for filename in ("rust.lcov", "go.out"):
        path = output / filename
        if path.exists():
            path.unlink()
    (output / "comment.md").write_text(body)
    if rust:
        with (output / "rust.lcov").open("w") as stream:
            for source in sorted({source for source, _ in rust}):
                stream.write(f"SF:{source}\n")
                for (file, line), hit in sorted(rust.items()):
                    if file == source:
                        stream.write(f"DA:{line},{int(hit)}\n")
                stream.write("end_of_record\n")
    if go:
        (output / "go.out").write_text("mode: set\n" + "".join(
            f"{location} {count} {int(hit)}\n" for location, (count, hit) in sorted(go.items())))
    print(body)
    if args.dry_run:
        return
    for pr in prs:
        number = int(pr["number"])
        endpoint = f"repos/{repo}/issues/{number}/comments"
        pages = gh(endpoint + "?per_page=100", pages=True)
        existing = [item for page in pages for item in page
                    if item["user"]["login"] == "github-actions[bot]"
                    and item["user"]["type"] == "Bot" and item["body"].startswith(MARKER)]
        if len(existing) > 1:
            raise ValueError("multiple coverage bot comments")
        if existing and newer_comment(existing[0]["body"], run):
            continue
        if not matching_pr(gh(f"repos/{repo}/pulls/{number}"), run, repo):
            continue
        gh(f'repos/{repo}/issues/comments/{existing[0]["id"]}' if existing else endpoint, payload={"body": body})
        if "GITHUB_OUTPUT" in os.environ:
            with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
                stream.write(f"pr={number}\n")


if __name__ == "__main__":
    main()
