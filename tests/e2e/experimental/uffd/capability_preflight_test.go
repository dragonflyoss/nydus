package uffd

import (
	"os"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"golang.org/x/sys/unix"
)

// TestCapabilityPreflight checks the runner before the fault cases rely on
// it: the userfaultfd syscall, the UFFDIO_API handshake, MISSING-mode
// registration and the WAKE/COPY/ZEROPAGE ioctls. It logs what the runner
// offers, so a missing capability is diagnosable from this test alone.
func TestCapabilityPreflight(t *testing.T) {
	t.Parallel()
	var uts unix.Utsname
	if unix.Uname(&uts) == nil {
		t.Logf("runner kernel: %s %s", unix.ByteSliceToString(uts.Release[:]), unix.ByteSliceToString(uts.Version[:]))
	}
	if data, err := os.ReadFile("/proc/sys/vm/unprivileged_userfaultfd"); err == nil {
		t.Logf("vm.unprivileged_userfaultfd=%s euid=%d", strings.TrimSpace(string(data)), os.Geteuid())
	}
	err := probeCapability()
	env.Require(t, err == nil, "runner lacks userfaultfd: %v", err)
}
