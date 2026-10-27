# Known issues

Bugs the e2e suites reproduce but that are not fixed yet. A test of the
correct behavior wraps its body in `env.KnownIssue(t, "KI-N", ...)`.
CI sets `NYDUS_TEST_FAIL_KNOWN_ISSUES=1`: known bugs fail, and correct
behavior passes. The marker does not hide failures in PR checks.
Without that variable, local runs retain the diagnostic mode: skip while
the bug reproduces and fail when the marker becomes stale.
Fixing a bug means deleting its row and the marker in the same change.

No cases currently carry a known-issue marker.

The former KI-12 timeout case now disables speculative readahead and reads
one page at a time. CI export logs showed successive 4 KiB reads each failing
after the configured request timeout and retry, rather than one backend
request hanging. Synchronous EROFS readahead accumulated those independent
timeouts before returning to the application. The test retains its 20-second
bound, retry assertion, and normal whole-file read after recovery.
