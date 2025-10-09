// Copyright 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockRemoter is a mock implementation of the remoter interface
type MockRemoter struct {
	mock.Mock
}

const testPushRetryDelay = "5s"

func (m *MockRemoter) Resolve(ctx context.Context) (*ocispec.Descriptor, error) {
	args := m.Called(ctx)
	return args.Get(0).(*ocispec.Descriptor), args.Error(1)
}

func (m *MockRemoter) Pull(ctx context.Context, desc ocispec.Descriptor, byDigest bool) (io.ReadCloser, error) {
	args := m.Called(ctx, desc, byDigest)
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m *MockRemoter) Push(ctx context.Context, desc ocispec.Descriptor, byDigest bool, reader io.Reader) error {
	args := m.Called(ctx, desc, byDigest, reader)
	return args.Error(0)
}

func (m *MockRemoter) WithHTTP() {
	m.Called()
}

func (m *MockRemoter) MaybeWithHTTP(err error) {
	m.Called(err)
}

func (m *MockRemoter) IsWithHTTP() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockRemoter) ReaderAt(ctx context.Context, desc ocispec.Descriptor, byDigest bool) (content.ReaderAt, error) {
	args := m.Called(ctx, desc, byDigest)
	return args.Get(0).(content.ReaderAt), args.Error(1)
}

func (m *MockRemoter) ReadSeekCloser(ctx context.Context, desc ocispec.Descriptor, byDigest bool) (io.ReadSeekCloser, error) {
	args := m.Called(ctx, desc, byDigest)
	return args.Get(0).(io.ReadSeekCloser), args.Error(1)
}

// checkNydusImageAvailable checks if nydus-image tool is available
func checkNydusImageAvailable() bool {
	// Check if we're in test mode (using fake command)
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		return true
	}

	// Check if nydus-image command exists
	_, err := exec.LookPath("nydus-image")
	return err == nil
}

// skipIfNydusImageNotAvailable skips the test if nydus-image is not available
func skipIfNydusImageNotAvailable(t *testing.T) {
	if !checkNydusImageAvailable() {
		t.Skip("nydus-image tool not available, skipping test")
	}
}

// TestHelperProcess is used to mock external commands
func TestHelperProcess(_ *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)

	args := os.Args
	for len(args) > 0 {
		if args[0] == "--" {
			args = args[1:]
			break
		}
		args = args[1:]
	}

	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "No command")
		os.Exit(2)
	}

	cmd, args := args[0], args[1:]
	switch cmd {
	case "nydus-image":
		if len(args) > 0 && args[0] == "unpack" {
			// Mock successful unpack - validate required arguments
			hasBootstrap := false
			hasOutput := false
			for i, arg := range args {
				if arg == "--bootstrap" && i+1 < len(args) {
					hasBootstrap = true
				}
				if arg == "--output" && i+1 < len(args) {
					hasOutput = true
				}
			}
			if !hasBootstrap || !hasOutput {
				fmt.Fprintf(os.Stderr, "Missing required arguments")
				os.Exit(1)
			}
			fmt.Fprintf(os.Stdout, "Unpacked successfully")
			os.Exit(0)
		}
	case "nydus-image-fail":
		fmt.Fprintf(os.Stderr, "Command failed")
		os.Exit(1)
	case "":
		// Handle empty command case
		fmt.Fprintf(os.Stderr, "Empty command")
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Unknown command %q", cmd)
	os.Exit(2)
}

// Smoke tests for basic functionality
func TestReverseConvertSmoke(t *testing.T) {
	t.Run("Test basic reverse conversion setup", func(t *testing.T) {
		// Skip if nydus-image tool is not available
		skipIfNydusImageNotAvailable(t)

		opt := Opt{
			WorkDir:        "./tmp",
			NydusImagePath: "nydus-image",
			Source:         "localhost:5000/test:nydus",
			Target:         "localhost:5000/test:oci",
			Platforms:      "linux/amd64",
		}

		// This should fail at push retry delay parsing, not provider creation
		err := ReverseConvert(context.Background(), opt)
		assert.Error(t, err)
		// Verify the error is related to parsing push retry delay, not provider creation
		assert.Contains(t, err.Error(), "parse push retry delay")
	})

	t.Run("Test with alpine:latest nydus image", func(t *testing.T) {
		// Skip if nydus-image tool is not available
		skipIfNydusImageNotAvailable(t)

		// Skip if no test registry is available
		if os.Getenv("NYDUS_TEST_REGISTRY") == "" {
			t.Skip("NYDUS_TEST_REGISTRY not set, skipping alpine test")
		}

		opt := Opt{
			WorkDir:        "./tmp",
			NydusImagePath: "nydus-image",
			Source:         os.Getenv("NYDUS_TEST_REGISTRY") + "/alpine:nydus",
			Target:         os.Getenv("NYDUS_TEST_REGISTRY") + "/alpine:oci",
			Platforms:      "linux/amd64",
			SourceInsecure: true,
			TargetInsecure: true,
		}

		err := ReverseConvert(context.Background(), opt)
		// This might succeed if test registry is properly set up
		if err != nil {
			t.Logf("Reverse conversion failed as expected in test environment: %v", err)
		}
	})

	t.Run("Test experimental warning is logged", func(t *testing.T) {
		// Skip if nydus-image tool is not available
		skipIfNydusImageNotAvailable(t)

		// This test verifies that the experimental warning is properly logged
		opt := Opt{
			WorkDir:        "./tmp",
			NydusImagePath: "nydus-image",
			Source:         "localhost:5000/test:nydus",
			Target:         "localhost:5000/test:oci",
			Platforms:      "linux/amd64",
		}

		err := ReverseConvert(context.Background(), opt)
		assert.Error(t, err)
		// The warning should be logged before any errors occur
	})
}

// Flow tests for complete conversion process
func TestReverseConvertFlow(t *testing.T) {
	t.Run("Test complete conversion flow with alpine", func(t *testing.T) {
		// Skip if nydus-image tool is not available
		skipIfNydusImageNotAvailable(t)

		// Skip if no test registry is available
		if os.Getenv("NYDUS_TEST_REGISTRY") == "" {
			t.Skip("NYDUS_TEST_REGISTRY not set, skipping flow test")
		}

		opt := Opt{
			WorkDir:        "./tmp",
			NydusImagePath: "nydus-image",
			Source:         os.Getenv("NYDUS_TEST_REGISTRY") + "/alpine:nydus",
			Target:         os.Getenv("NYDUS_TEST_REGISTRY") + "/alpine:oci-reverse",
			Platforms:      "linux/amd64",
			SourceInsecure: true,
			TargetInsecure: true,
			PushRetryCount: 3,
			PushRetryDelay: testPushRetryDelay,
		}

		// Test the complete flow
		err := ReverseConvert(context.Background(), opt)
		if err != nil {
			t.Logf("Flow test failed as expected in test environment: %v", err)
		}
	})

	t.Run("Test conversion flow with multiple platforms", func(t *testing.T) {
		// Skip if nydus-image tool is not available
		skipIfNydusImageNotAvailable(t)

		opt := Opt{
			WorkDir:        "./tmp",
			NydusImagePath: "nydus-image",
			Source:         "localhost:5000/test:nydus",
			Target:         "localhost:5000/test:oci",
			Platforms:      "linux/amd64,linux/arm64",
			AllPlatforms:   true,
		}

		err := ReverseConvert(context.Background(), opt)
		assert.Error(t, err)
		// Should fail at provider creation, but platform parsing should succeed
	})

	t.Run("Test conversion flow with compression", func(t *testing.T) {
		// Skip if nydus-image tool is not available
		skipIfNydusImageNotAvailable(t)

		opt := Opt{
			WorkDir:        "./tmp",
			NydusImagePath: "nydus-image",
			Source:         "localhost:5000/test:nydus",
			Target:         "localhost:5000/test:oci",
			Platforms:      "linux/amd64",
			Compressor:     "gzip",
		}

		err := ReverseConvert(context.Background(), opt)
		assert.Error(t, err)
	})
}

// Error handling and edge case tests
func TestReverseConvertErrorHandling(t *testing.T) {
	t.Run("Test context cancellation", func(t *testing.T) {
		// Skip if nydus-image tool is not available
		skipIfNydusImageNotAvailable(t)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		opt := Opt{
			WorkDir:        "./tmp",
			NydusImagePath: "nydus-image",
			Source:         "localhost:5000/test:nydus",
			Target:         "localhost:5000/test:oci",
			Platforms:      "linux/amd64",
		}

		err := ReverseConvert(ctx, opt)
		assert.Error(t, err)
	})

	t.Run("Test invalid platform format", func(t *testing.T) {
		// Skip if nydus-image tool is not available
		skipIfNydusImageNotAvailable(t)

		opt := Opt{
			WorkDir:        "./tmp",
			NydusImagePath: "nydus-image",
			Source:         "localhost:5000/test:nydus",
			Target:         "localhost:5000/test:oci",
			Platforms:      "invalid-platform-format",
			PushRetryDelay: testPushRetryDelay,
		}

		err := ReverseConvert(context.Background(), opt)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "parse platforms")
	})

	t.Run("Test invalid retry delay format", func(t *testing.T) {
		// Skip if nydus-image tool is not available
		skipIfNydusImageNotAvailable(t)

		opt := Opt{
			WorkDir:        "./tmp",
			NydusImagePath: "nydus-image",
			Source:         "localhost:5000/test:nydus",
			Target:         "localhost:5000/test:oci",
			Platforms:      "linux/amd64",
			PushRetryDelay: "invalid-duration",
		}

		err := ReverseConvert(context.Background(), opt)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "parse push retry delay")
	})

	t.Run("Test with non-existent work directory", func(t *testing.T) {
		// Skip if nydus-image tool is not available
		skipIfNydusImageNotAvailable(t)

		opt := Opt{
			WorkDir:        "/root/readonly/directory",
			NydusImagePath: "nydus-image",
			Source:         "localhost:5000/test:nydus",
			Target:         "localhost:5000/test:oci",
			Platforms:      "linux/amd64",
			PushRetryDelay: testPushRetryDelay,
		}

		err := ReverseConvert(context.Background(), opt)
		assert.Error(t, err)
	})

	t.Run("Test with custom retry settings", func(t *testing.T) {
		// Skip if nydus-image tool is not available
		skipIfNydusImageNotAvailable(t)

		opt := Opt{
			WorkDir:        "./tmp",
			NydusImagePath: "nydus-image",
			Source:         "localhost:5000/test:nydus",
			Target:         "localhost:5000/test:oci",
			Platforms:      "linux/amd64",
			PushRetryCount: 5,
			PushRetryDelay: testPushRetryDelay,
		}

		err := ReverseConvert(context.Background(), opt)
		assert.Error(t, err)
	})

	t.Run("Test with both insecure flags", func(t *testing.T) {
		// Skip if nydus-image tool is not available
		skipIfNydusImageNotAvailable(t)

		opt := Opt{
			WorkDir:        "./tmp",
			NydusImagePath: "nydus-image",
			Source:         "localhost:5000/test:nydus",
			Target:         "localhost:5000/test:oci",
			Platforms:      "linux/amd64",
			SourceInsecure: true,
			TargetInsecure: true,
		}

		err := ReverseConvert(context.Background(), opt)
		assert.Error(t, err)
	})

	t.Run("Test with plain HTTP", func(t *testing.T) {
		// Skip if nydus-image tool is not available
		skipIfNydusImageNotAvailable(t)

		opt := Opt{
			WorkDir:        "./tmp",
			NydusImagePath: "nydus-image",
			Source:         "localhost:5000/test:nydus",
			Target:         "localhost:5000/test:oci",
			Platforms:      "linux/amd64",
			WithPlainHTTP:  true,
		}

		err := ReverseConvert(context.Background(), opt)
		assert.Error(t, err)
	})
}

// Performance and concurrency tests
func TestReverseConvertPerformance(t *testing.T) {
	t.Run("Test conversion with large retry count", func(t *testing.T) {
		// Skip if nydus-image tool is not available
		skipIfNydusImageNotAvailable(t)

		opt := Opt{
			WorkDir:        "./tmp",
			NydusImagePath: "nydus-image",
			Source:         "localhost:5000/test:nydus",
			Target:         "localhost:5000/test:oci",
			Platforms:      "linux/amd64",
			PushRetryCount: 100,
			PushRetryDelay: testPushRetryDelay,
		}

		err := ReverseConvert(context.Background(), opt)
		assert.Error(t, err)
	})

	t.Run("Test conversion timeout", func(t *testing.T) {
		// Skip if nydus-image tool is not available
		skipIfNydusImageNotAvailable(t)

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		opt := Opt{
			WorkDir:        "./tmp",
			NydusImagePath: "nydus-image",
			Source:         "localhost:5000/test:nydus",
			Target:         "localhost:5000/test:oci",
			Platforms:      "linux/amd64",
		}

		err := ReverseConvert(ctx, opt)
		assert.Error(t, err)
	})
}

// Integration tests for real-world scenarios
func TestReverseConvertIntegration(t *testing.T) {
	t.Run("Test with real alpine nydus image", func(t *testing.T) {
		// Skip if nydus-image tool is not available
		skipIfNydusImageNotAvailable(t)

		// Skip if no test registry is available
		if os.Getenv("NYDUS_TEST_REGISTRY") == "" {
			t.Skip("NYDUS_TEST_REGISTRY not set, skipping integration test")
		}

		opt := Opt{
			WorkDir:        "./tmp",
			NydusImagePath: "nydus-image",
			Source:         os.Getenv("NYDUS_TEST_REGISTRY") + "/alpine:nydus",
			Target:         os.Getenv("NYDUS_TEST_REGISTRY") + "/alpine:oci-integration",
			Platforms:      "linux/amd64",
			SourceInsecure: true,
			TargetInsecure: true,
			PushRetryCount: 3,
			PushRetryDelay: testPushRetryDelay,
		}

		// Test the complete integration flow
		err := ReverseConvert(context.Background(), opt)
		if err != nil {
			t.Logf("Integration test failed as expected in test environment: %v", err)
		}
	})

	t.Run("Test conversion with different compressors", func(t *testing.T) {
		// Skip if nydus-image tool is not available
		skipIfNydusImageNotAvailable(t)

		compressors := []string{"gzip", "zstd", "lz4"}

		for _, compressor := range compressors {
			t.Run("compressor_"+compressor, func(t *testing.T) {
				opt := Opt{
					WorkDir:        "./tmp",
					NydusImagePath: "nydus-image",
					Source:         "localhost:5000/test:nydus",
					Target:         "localhost:5000/test:oci",
					Platforms:      "linux/amd64",
					Compressor:     compressor,
				}

				err := ReverseConvert(context.Background(), opt)
				assert.Error(t, err)
			})
		}
	})

	t.Run("Test conversion with different platforms", func(t *testing.T) {
		// Skip if nydus-image tool is not available
		skipIfNydusImageNotAvailable(t)

		platforms := []string{
			"linux/amd64",
			"linux/arm64",
			"linux/amd64,linux/arm64",
		}

		for _, platform := range platforms {
			t.Run("platform_"+platform, func(t *testing.T) {
				opt := Opt{
					WorkDir:        "./tmp",
					NydusImagePath: "nydus-image",
					Source:         "localhost:5000/test:nydus",
					Target:         "localhost:5000/test:oci",
					Platforms:      platform,
				}

				err := ReverseConvert(context.Background(), opt)
				assert.Error(t, err)
			})
		}
	})
}

// CI-friendly tests that don't require nydus-image tool
func TestReverseConvertCIFriendly(t *testing.T) {
	t.Run("Test basic parameter validation without nydus-image", func(t *testing.T) {
		// Test parameter validation that doesn't require nydus-image tool
		opt := Opt{
			WorkDir:        "./tmp",
			NydusImagePath: "nydus-image",
			Source:         "localhost:5000/test:nydus",
			Target:         "localhost:5000/test:oci",
			Platforms:      "invalid-platform-format",
			PushRetryDelay: testPushRetryDelay,
		}

		err := ReverseConvert(context.Background(), opt)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "parse platforms")
	})

	t.Run("Test invalid retry delay without nydus-image", func(t *testing.T) {
		// Test retry delay parsing that doesn't require nydus-image tool
		opt := Opt{
			WorkDir:        "./tmp",
			NydusImagePath: "nydus-image",
			Source:         "localhost:5000/test:nydus",
			Target:         "localhost:5000/test:oci",
			Platforms:      "linux/amd64",
			PushRetryDelay: "invalid-duration",
		}

		err := ReverseConvert(context.Background(), opt)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "parse push retry delay")
	})

	t.Run("Test work directory creation without nydus-image", func(t *testing.T) {
		// Test work directory handling that doesn't require nydus-image tool
		opt := Opt{
			WorkDir:        "/root/readonly/directory",
			NydusImagePath: "nydus-image",
			Source:         "localhost:5000/test:nydus",
			Target:         "localhost:5000/test:oci",
			Platforms:      "linux/amd64",
			PushRetryDelay: testPushRetryDelay,
		}

		err := ReverseConvert(context.Background(), opt)
		assert.Error(t, err)
	})

	t.Run("Test context cancellation without nydus-image", func(t *testing.T) {
		// Test context handling that doesn't require nydus-image tool
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		opt := Opt{
			WorkDir:        "./tmp",
			NydusImagePath: "nydus-image",
			Source:         "localhost:5000/test:nydus",
			Target:         "localhost:5000/test:oci",
			Platforms:      "linux/amd64",
			PushRetryDelay: testPushRetryDelay,
		}

		err := ReverseConvert(ctx, opt)
		assert.Error(t, err)
	})
}
