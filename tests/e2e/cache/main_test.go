package cache

import (
	"fmt"
	"os"
	"testing"
)

// TestMain owns the directory the package's images are built in, so every
// test can share them and they go away with the binary.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "nydus-e2e-cache-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create image root: %v\n", err)
		os.Exit(1)
	}
	// Daemons may read the images under another uid.
	if err := os.Chmod(dir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "chmod image root: %v\n", err)
		os.Exit(1)
	}
	imageRoot = dir
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
