import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

import coverage_comment as report


SOURCE = "github.com/dragonflyoss/nydus/nydusify/pkg/nydus/pack.go"


class CoverageCommentTests(unittest.TestCase):
    def test_cli_help_formats_percent_threshold(self):
        output = io.StringIO()
        with mock.patch("sys.argv", ["coverage_comment.py", "--help"]), \
                contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as caught:
            report.main()
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("90%", output.getvalue())

    def test_gate_uses_exact_thresholds_and_requires_both_languages(self):
        rust = {("nydus/src/lib.rs", line): line < 9 for line in range(10)}
        go = {SOURCE + ":1.1,2.2": (9, True), SOURCE + ":3.1,4.2": (1, False)}
        self.assertEqual(report.threshold_failures(rust, go), [])
        go = {SOURCE + ":1.1,2.2": (89999, True), SOURCE + ":3.1,4.2": (10001, False)}
        self.assertEqual(len(report.threshold_failures(rust, go)), 1)
        self.assertEqual(len(report.threshold_failures({}, {})), 2)
        rust[("nydus/src/lib.rs", 0)] = False
        self.assertEqual(len(report.threshold_failures(rust, go)), 2)

    def test_directory_gate_rejects_missing_failed_and_malformed_shards(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in report.EXPECTED:
                shard = root / name
                shard.mkdir()
                (shard / "status.txt").write_text("test_outcome=success\n")
                filename = "rust-unit-integration.lcov" if name == "coverage-rust-unit-integration" else "rust-e2e.lcov"
                (shard / filename).write_text("SF:nydus/src/lib.rs\nDA:1,1\nend_of_record\n")
            image = root / "coverage-e2e-image-tools"
            go = f"mode: set\n{SOURCE}:1.1,2.2 9 1\n{SOURCE}:3.1,4.2 1 0\n"
            for filename in ("go-e2e.out", "go-unit-integration.out"):
                (image / filename).write_text(go)
            with mock.patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(root / "summary")}), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(report.check_directory(root), 0)
                (image / "status.txt").write_text("test_outcome=failure\n")
                self.assertEqual(report.check_directory(root), 1)
                (image / "status.txt").write_text("test_outcome=success\n")
                (image / "go-e2e.out").write_text("malformed\n")
                self.assertEqual(report.check_directory(root), 1)
                (image / "go-e2e.out").unlink()
                self.assertEqual(report.check_directory(root), 1)

    def test_rerun_uses_newest_shard_not_old_success(self):
        name = "coverage-e2e-storage-recovery"
        old = {"name": name, "id": 1, "created_at": "2026-01-01T00:00:00Z", "expired": False}
        new = dict(old, id=2, created_at="2026-01-01T00:01:00Z")
        unrelated = dict(new, name="e2e-binaries")
        self.assertEqual(report.latest_artifacts([new, old, unrelated]), {name: new})
        new["expired"] = True
        self.assertEqual(report.latest_artifacts([new, old]), {name: new})

    def test_rust_union_and_workspace_paths(self):
        text = "SF:/home/runner/work/nydus/nydus/nydus-core/src/reader.rs\nDA:3,0\nDA:4,2\nend_of_record\n"
        first = report.rust_lines(text)
        second = report.rust_lines(text.replace("/home/runner/work/nydus/nydus/", "/tmp/work/").replace("3,0", "3,1"))
        first.update({key: first.get(key, False) or hit for key, hit in second.items()})
        self.assertEqual(first, {("nydus-core/src/reader.rs", 3): True, ("nydus-core/src/reader.rs", 4): True})
        with self.assertRaises(ValueError):
            report.rust_lines(text.replace("3,0", "0,1"))
        with self.assertRaises(ValueError):
            report.rust_lines(text.replace("3,0", "3,-1"))
        with self.assertRaises(ValueError):
            report.rust_lines(text.replace("nydus-core/src/reader.rs", "nydus-core/src/../../secret.rs"))

    def test_go_union_and_layout_validation(self):
        first = report.go_blocks(f"mode: atomic\n{SOURCE}:1.1,2.2 3 0\n{SOURCE}:4.1,5.2 2 8\n")
        second = report.go_blocks(f"mode: set\n{SOURCE}:1.1,2.2 3 1\n{SOURCE}:4.1,5.2 2 0\n")
        report.merge_go(first, second)
        report.merge_go(first, second)
        self.assertEqual(sum(n for n, hit in first.values() if hit), 5)
        repeated = report.go_blocks(f"mode: atomic\n{SOURCE}:1.1,2.2 3 0\n{SOURCE}:1.1,2.2 3 8\n")
        self.assertEqual(repeated, {SOURCE + ":1.1,2.2": (3, True)})
        with self.assertRaisesRegex(ValueError, "incompatible"):
            report.go_blocks(f"mode: atomic\n{SOURCE}:1.1,2.2 3 0\n{SOURCE}:1.1,2.2 4 8\n")
        for change in (
            f"mode: set\n{SOURCE}:1.1,2.2 4 1\n{SOURCE}:4.1,5.2 2 0\n",
            f"mode: set\n{SOURCE}:1.1,3.2 3 1\n",
        ):
            with self.assertRaisesRegex(ValueError, "incompatible"):
                report.merge_go(first, report.go_blocks(change))
        for text in ("mode: nonsense", f"mode: set\n{SOURCE}:1.1,2.2 3 -1\n"):
            with self.assertRaises(ValueError):
                report.go_blocks(text)

    def test_archive_allowlist_and_limits(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("status.txt", "test_outcome=success")
            archive.writestr("../status.txt", "untrusted")
            archive.writestr("raw/rust/ignored.profraw", "raw")
            archive.writestr("run.sh", "exit 1")
        self.assertEqual(report.reports_from_zip(buffer.getvalue()), {"status.txt": "test_outcome=success"})
        with self.assertRaises(ValueError):
            report.reports_from_zip(b"x" * (report.MAX_ZIP + 1))
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("status.txt", "x" * (report.MAX_REPORT + 1))
        with self.assertRaisesRegex(ValueError, "oversized"):
            report.reports_from_zip(buffer.getvalue())

    def test_failed_missing_and_invalid_shards_are_not_zero(self):
        rust, go, problems = report.merge_reports({
            "coverage-e2e-fuse": {
                "status.txt": "test_outcome=failure",
                "rust-e2e.lcov": "SF:/tmp/nydus/src/lib.rs\nDA:2,1\nDA:3,0\nend_of_record\n",
            },
            "coverage-e2e-image-tools": {
                "status.txt": "test_outcome=success",
                "go-e2e.out": "mode: set\ninvalid\n",
            },
        })
        self.assertEqual(len(rust), 2)
        self.assertFalse(go)
        self.assertTrue(any("tests failed" in item for item in problems))
        self.assertTrue(any("missing or expired" in item for item in problems))
        self.assertTrue(any("invalid report" in item for item in problems))
        body = report.comment(self.sample_run(), rust, go, problems)
        self.assertIn("1 / 2 (50.00%)", body)
        self.assertIn("No usable report", body)
        self.assertIn("Partial results", body)

    @staticmethod
    def sample_run():
        return {"id": 12, "run_attempt": 2, "head_sha": "a" * 40, "html_url": "https://github.com/org/repo/actions/runs/12",
                "conclusion": "failure", "head_repository": {"full_name": "fork/repo"}, "head_branch": "topic"}

    def test_stale_run_and_fork_identity(self):
        run = self.sample_run()
        body = report.comment(run, {}, {}, [])
        self.assertFalse(report.newer_comment(body, run))
        self.assertTrue(report.newer_comment(body.replace("attempt=2", "attempt=3"), run))
        self.assertTrue(report.newer_comment(body.replace("run=12", "run=13"), run))
        pr = {"state": "open", "base": {"repo": {"full_name": "org/repo"}},
              "head": {"sha": "a" * 40, "repo": {"full_name": "fork/repo"}}}
        self.assertTrue(report.matching_pr(pr, run, "org/repo"))
        pr["head"]["sha"] = "b" * 40
        self.assertFalse(report.matching_pr(pr, run, "org/repo"))
        pr["head"]["sha"] = "a" * 40
        pr["head"]["repo"] = {"full_name": "other/repo"}
        self.assertFalse(report.matching_pr(pr, run, "org/repo"))

    def test_update_only_our_bot_and_recheck_head(self):
        run = dict(self.sample_run(), path=".github/workflows/ci.yml", status="completed", event="pull_request")
        pr = {"number": 4, "state": "open", "base": {"repo": {"full_name": "org/repo"}},
              "head": {"sha": "a" * 40, "repo": {"full_name": "fork/repo"}}}
        for own_comment, stale in ((False, False), (True, False), (True, True)):
            with self.subTest(own_comment=own_comment, stale=stale), tempfile.TemporaryDirectory() as tmp:
                existing = {"id": 7, "body": report.comment(run, {}, {}, []),
                            "user": {"login": "github-actions[bot]" if own_comment else "person",
                                     "type": "Bot" if own_comment else "User"}}
                live = dict(pr, head=dict(pr["head"], sha="b" * 40)) if stale else pr
                responses = [run, [pr], {"total_count": 0, "artifacts": []}, [[existing]], live]
                if not stale:
                    responses.append({})
                with mock.patch.object(report, "gh", side_effect=responses) as api, \
                        mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": "org/repo", "COVERAGE_RUN_ID": "12",
                                                     "GITHUB_OUTPUT": str(Path(tmp) / "outputs")}), \
                        mock.patch.object(report, "Path", side_effect=lambda name: Path(tmp) / name), \
                        mock.patch("sys.argv", ["coverage_comment.py"]), \
                        contextlib.redirect_stdout(io.StringIO()):
                    report.main()
                if stale:
                    self.assertEqual(api.call_count, 5)
                else:
                    endpoint = "repos/org/repo/issues/comments/7" if own_comment else "repos/org/repo/issues/4/comments"
                    self.assertEqual(api.call_args[0], (endpoint,))
                    self.assertIn("Partial results", api.call_args[1]["payload"]["body"])


if __name__ == "__main__":
    unittest.main()
