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
//! Under CI (the `CI` environment variable), only the correct behavior passes.
//! Known bugs fail instead of being treated as expected failures.

use std::fmt::Debug;

/// Classifies the outcome of a test pinned to known issue `id`, such as
/// `"KI-5"`.
///
/// `correct` says whether `observed` is the behavior the issue expects,
/// `reproduces` whether it is the documented bug. Under CI only correct,
/// unambiguous behavior passes; otherwise only the reproduced bug passes.
///
/// # Panics
///
/// Under CI, when the outcome is not correct or also reproduces the bug.
/// Otherwise, when the issue is fixed (`correct`), when the outcome is
/// neither, or when the two classifiers overlap.
#[track_caller]
pub fn assert_known_issue(id: &str, observed: impl Debug, correct: bool, reproduces: bool) {
    classify(
        id,
        observed,
        correct,
        reproduces,
        std::env::var_os("CI").is_some(),
    );
}

/// Classifies the outcome as [`assert_known_issue`] does, `strict` being
/// whether it runs under CI.
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
    use super::*;

    #[test]
    fn classify_passes_the_bug_or_the_strict_fix() {
        let test_cases = vec![("bug", false, true, false), ("fixed", true, false, true)];

        for (observed, correct, reproduces, strict) in test_cases {
            classify("KI-0", observed, correct, reproduces, strict);
        }
    }

    #[test]
    #[should_panic(expected = "KI-0 no longer reproduces")]
    fn classify_fails_once_the_bug_is_fixed() {
        classify("KI-0", "fixed", true, false, false);
    }

    #[test]
    #[should_panic(expected = "neither the correct behavior nor the known bug")]
    fn classify_fails_on_an_unexpected_outcome() {
        classify("KI-0", "other", false, false, false);
    }

    #[test]
    #[should_panic(expected = "both correct and the known bug")]
    fn classify_fails_on_an_ambiguous_outcome() {
        classify("KI-0", "ambiguous", true, true, false);
    }

    #[test]
    #[should_panic(expected = "expected correct behavior")]
    fn classify_strict_fails_when_the_bug_reproduces() {
        classify("KI-0", "bug", false, true, true);
    }

    #[test]
    #[should_panic(expected = "expected correct behavior")]
    fn classify_strict_fails_on_an_ambiguous_outcome() {
        classify("KI-0", "ambiguous", true, true, true);
    }
}
