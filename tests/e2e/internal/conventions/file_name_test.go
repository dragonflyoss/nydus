package conventions

import "testing"

// TestFileName pins the test-to-file naming rule.
func TestFileName(t *testing.T) {
	t.Parallel()
	for fn, want := range map[string]string{
		"TestFUSE":             "fuse_test.go",
		"TestFileio":           "fileio_test.go",
		"TestTarGNUSparse":     "tar_gnu_sparse_test.go",
		"TestExportRoundtrip":  "export_roundtrip_test.go",
		"TestNoXattr":          "no_xattr_test.go",
		"TestD1ReadViaP2P":     "d1_read_via_p2p_test.go",
		"TestCrashLoop":        "crash_loop_test.go",
		"TestENOSPC":           "enospc_test.go",
		"FuzzTarHeader":        "fuzz_tar_header_test.go",
		"TestBackendError_404": "backend_error_404_test.go",
	} {
		if got := fileName(fn); got != want {
			t.Errorf("fileName(%s) = %s, want %s", fn, got, want)
		}
	}
}
