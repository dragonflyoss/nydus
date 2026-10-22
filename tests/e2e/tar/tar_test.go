package tar

import (
	"fmt"
	"os"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util"
)

// nydusBin is the nydus binary every test in the package drives, NYDUS_BIN
// or the in-tree build.
var nydusBin string

// TestMain is the entry of the tar conversion suite, resolving the nydus
// binary under test once before the tests run.
func TestMain(m *testing.M) {
	var err error
	if nydusBin, err = util.LookupExecutableFromEnv("NYDUS_BIN", "nydus"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}
