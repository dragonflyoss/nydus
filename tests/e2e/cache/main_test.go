package cache

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "nydus-e2e-cache-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create image root: %v\n", err)
		os.Exit(1)
	}

	if err := os.Chmod(dir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "chmod image root: %v\n", err)
		os.Exit(1)
	}

	imageRoot = dir
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
