package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util"
)

var (
	// nydusBin is the nydus binary every test in the suite drives, NYDUS_BIN
	// or the in-tree build.
	nydusBin string

	// nydusifyBin is the nydusify binary the image tests drive, NYDUSIFY_BIN
	// or the in-tree build.
	nydusifyBin string
)

// TestMain is the entry of the e2e suite. It hands the re-exec of this test
// binary over to the uffd child helper, resolves the binaries under test once
// and logs the nydus version before the tests run.
func TestMain(m *testing.M) {
	if os.Getenv(uffdChildModeEnv) == uffdChildModeOutstandingFault {
		os.Exit(runUffdOutstandingFaultChild())
	}

	var err error
	if nydusBin, err = util.LookupExecutableFromEnv("NYDUS_BIN", "nydus"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if nydusifyBin, err = util.LookupExecutableFromEnv("NYDUSIFY_BIN", "nydusify"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	version, err := exec.Command(nydusBin, "--version").CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s --version: %v: %s", nydusBin, err, version)
		os.Exit(1)
	}
	fmt.Printf("%s: %s\n", nydusBin, strings.TrimSpace(string(version)))

	os.Exit(m.Run())
}
