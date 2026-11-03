package env

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// kernelRelease returns the running kernel's release string.
func kernelRelease() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return ""
	}

	return unix.ByteSliceToString(uts.Release[:])
}

// KernelVersion returns the running kernel's major and minor version.
func KernelVersion() (major, minor int) {
	_, _ = fmt.Sscanf(kernelRelease(), "%d.%d", &major, &minor)
	return major, minor
}

// KernelAtLeast reports whether the running kernel is at least major.minor.
func KernelAtLeast(major, minor int) bool {
	gotMajor, gotMinor := KernelVersion()
	return gotMajor > major || (gotMajor == major && gotMinor >= minor)
}

// RequireKernel requires at least major.minor; why names the feature.
func RequireKernel(t testing.TB, major, minor int, why string) {
	t.Helper()
	gotMajor, gotMinor := KernelVersion()
	Require(t, KernelAtLeast(major, minor), "kernel %d.%d < %d.%d: %s", gotMajor, gotMinor, major, minor, why)
}

// HasFilesystem reports whether the kernel lists fsType in /proc/filesystems,
// loading its module first when it is not built in.
func HasFilesystem(fsType string) bool {
	if listsFilesystem(fsType) {
		return true
	}

	_ = exec.Command("modprobe", fsType).Run()

	return listsFilesystem(fsType)
}

func listsFilesystem(fsType string) bool {
	data, err := os.ReadFile("/proc/filesystems")
	if err != nil {
		return false
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[len(fields)-1] == fsType {
			return true
		}
	}

	return false
}

// RequireFilesystem requires kernel support for fsType.
func RequireFilesystem(t testing.TB, fsType string) {
	t.Helper()
	Require(t, HasFilesystem(fsType), "kernel lacks %s support", fsType)
}
