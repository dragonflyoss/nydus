package nydusify

import (
	"context"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/stretchr/testify/assert"
)

const (
	nydusBlobMediaType       = "application/vnd.oci.image.layer.nydus.blob.v1"
	nydusBlobAnnotation      = "containerd.io/snapshot/nydus-blob"
	nydusOptimizedAnnotation = "containerd.io/snapshot/nydus-blob-optimized"
	nydusBootstrapAnnotation = "containerd.io/snapshot/nydus-bootstrap"
	bootstrapInLayer         = "image/image.boot"
)

func nydusify(t testing.TB, args ...string) string {
	t.Helper()
	out, err := tryNydusify(t, args...)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return out
}

func tryNydusify(t testing.TB, args ...string) (string, error) {
	t.Helper()
	args = append(slices.Clone(args), "--builder", env.Nydus(t), "--target-plain-http")
	if args[0] != "mount" {
		args = append(args, "--source-plain-http")
	}

	if args[0] == "check" && !slices.Contains(args, "--work-dir") {
		args = append(args, "--work-dir", t.TempDir())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, env.Nydusify(t), args...).CombinedOutput()

	if !assert.NoError(t, ctx.Err()) {
		t.FailNow()
	}

	return string(out), err
}
