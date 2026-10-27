//! Markers for tests that pin a tracked bug, the Rust counterpart of the Go
//! suites' `env.KnownIssue` (see `tests/e2e/KNOWN_ISSUES.md`).
//!
//! A known-issue test runs the scenario once and classifies what it
//! observed: the correct behavior, the documented bug, or neither. While
//! the bug reproduces the test passes and says so on stderr. Once the
//! correct behavior shows up the test fails, so the fix also deletes the
//! row in `KNOWN_ISSUES.md` and turns the marker into a plain assertion of
//! the correct behavior. Anything else is a regression and fails as well.
//!
//! With `NYDUS_TEST_FAIL_KNOWN_ISSUES=1` (CI), only the correct behavior passes.
//! Known bugs fail instead of being treated as expected failures.

use std::fmt::Debug;

/// Classify the outcome of a test pinned to known issue `id` (`"KI-5"`).
///
/// `correct` says whether `observed` is the behavior the issue expects,
/// `reproduces` whether it is the documented bug. In strict CI mode only
/// correct, unambiguous behavior passes. Otherwise it passes only when the bug
/// reproduces; panics when the issue is fixed (`correct`), when the outcome
/// is neither, or when the two classifiers overlap.
#[track_caller]
pub fn assert_known_issue(id: &str, observed: impl Debug, correct: bool, reproduces: bool) {
    classify(
        id,
        observed,
        correct,
        reproduces,
        std::env::var("NYDUS_TEST_FAIL_KNOWN_ISSUES").as_deref() == Ok("1"),
    );
}

#[track_caller]
fn classify(id: &str, observed: impl Debug, correct: bool, reproduces: bool, strict: bool) {
    if strict {
        assert!(
            correct && !reproduces,
            "{id}: expected correct behavior, observed: {observed:?} (reproduces={reproduces})"
        );
        return;
    }
    match (correct, reproduces) {
        (true, true) => panic!(
            "{id}: the outcome classifies as both correct and the known bug, fix the test: {observed:?}"
        ),
        (true, false) => panic!(
            "{id} no longer reproduces: update tests/e2e/KNOWN_ISSUES.md and flip this test \
             to assert the correct behavior (observed: {observed:?})"
        ),
        (false, false) => panic!(
            "{id}: observed neither the correct behavior nor the known bug: {observed:?}"
        ),
        (false, true) => eprintln!("KNOWN ISSUE {id} reproduced: {observed:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::classify;

    #[test]
    fn passes_while_the_bug_reproduces() {
        classify("KI-0", "bug", false, true, false);
    }

    #[test]
    #[should_panic(expected = "KI-0 no longer reproduces")]
    fn fails_once_the_bug_is_fixed() {
        classify("KI-0", "fixed", true, false, false);
    }

    #[test]
    #[should_panic(expected = "neither the correct behavior nor the known bug")]
    fn fails_on_an_unexpected_outcome() {
        classify("KI-0", "other", false, false, false);
    }

    #[test]
    #[should_panic(expected = "expected correct behavior")]
    fn strict_mode_fails_when_the_bug_reproduces() {
        classify("KI-0", "bug", false, true, true);
    }

    #[test]
    fn strict_mode_passes_correct_behavior() {
        classify("KI-0", "fixed", true, false, true);
    }

    #[test]
    #[should_panic(expected = "expected correct behavior")]
    fn strict_mode_rejects_an_ambiguous_outcome() {
        classify("KI-0", "ambiguous", true, true, true);
    }
}
