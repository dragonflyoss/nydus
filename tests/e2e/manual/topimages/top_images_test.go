//go:build manual

// Package topimages converts and checks the most popular Docker Hub images
// with nydusify. It needs the network and hours, so it is built only with
// the manual tag:
//
//	sudo -E go test -tags manual -run TestTopImages -timeout 0 ./manual/topimages/
package topimages

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/stretchr/testify/require"
)

// TestTopImages runs `nydusify convert` and `nydusify check` over every
// image of the top-images list, pushing the converted images to a registry.
//
// Knobs (all optional):
//
//	NYDUSFS_TOP_IMAGES_REGISTRY        registry/namespace the converted images are
//	                                   pushed to (default "localhost:5000"); CI points
//	                                   it at GHCR (e.g. "ghcr.io/dragonflyoss/nydus")
//	                                   so the runner's root volume does not fill up
//	NYDUSFS_TOP_IMAGES_PLAIN_HTTP      talk to that registry over plain HTTP without
//	                                   TLS verification ("1"/"true"); defaults to
//	                                   true only for a localhost registry
//	NYDUSFS_TOP_IMAGES_PLATFORM        platform to convert and check (default
//	                                   "linux/amd64": the Windows manifests of
//	                                   multi-arch images cannot be extracted on
//	                                   Linux); "all" or empty converts every one
//	NYDUSFS_TOP_IMAGES_CONCURRENCY     images processed in parallel (default 5)
//	NYDUSFS_TOP_IMAGES_RETRIES         retries of a convert or check that hit a
//	                                   transient registry failure (default 5)
//	NYDUSFS_TOP_IMAGES_RETRY_INTERVAL  base wait between retries, growing linearly
//	                                   with each attempt (default 30s)
//	NYDUSFS_TOP_IMAGES_LIST            the image list (default
//	                                   tests/e2e/internal/corpus/top-images.txt)
//	NYDUSFS_TOP_IMAGES_WORKDIR         base of the per-image scratch directories;
//	                                   point it at a mount with ample space
//	                                   (default the test's temp dir)
//
// It needs root: convert preserves file ownership and check mounts the
// converted image through FUSE. An image the source registry no longer has
// is reported with a warning and passes.
func TestTopImages(t *testing.T) {
	t.Parallel()
	env.RequireRoot(t)
	cfg := loadConfig(t)
	images := readImageList(t, cfg.list)
	require.NotEmpty(t, images, "image list %q is empty", cfg.list)
	nydusify := env.Nydusify(t)
	nydus := env.Nydus(t)

	// Every image is a parallel subtest, so failures are reported per image,
	// with at most cfg.concurrency of them running at once.
	sem := make(chan struct{}, cfg.concurrency)
	total := len(images)
	var processed, succeeded atomic.Int64
	for _, image := range images {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			sem <- struct{}{}
			defer func() { <-sem }()
			defer func() {
				t.Logf("[progress] %d/%d images processed, %d succeeded",
					processed.Add(1), total, succeeded.Load())
			}()

			// The converted image goes next to its source in the target
			// namespace, suffixed so it does not collide with it (e.g.
			// ghcr.io/dragonflyoss/nydus/nginx -> .../nginx-nydus).
			target := fmt.Sprintf("%s/%s-nydus", cfg.registry, imageBaseName(image))

			// Removed as soon as the image is done, so scratch data does not
			// pile up across the parallel run.
			work, err := os.MkdirTemp(cfg.workBase, "nydusify-top-images-")
			require.NoError(t, err)
			defer func() { _ = os.RemoveAll(work) }()

			args := func(sub string) []string {
				args := []string{sub,
					"--source", image,
					"--target", target,
					"--builder", nydus,
					"--work-dir", filepath.Join(work, sub),
				}
				if cfg.platform != "" {
					args = append(args, "--platform", cfg.platform)
				}
				if cfg.plainHTTP {
					args = append(args, "--target-plain-http", "--target-insecure")
				}
				return args
			}

			out, err := runWithRetry(t, "convert "+image, cfg, func() *exec.Cmd { return exec.Command(nydusify, args("convert")...) })
			if err != nil && isImageNotFound(out) {
				// Some list entries are no longer published (e.g. the
				// deprecated `java` image); that is not a nydus failure.
				t.Logf("WARNING: %q not found in its registry; not converted", image)
				return
			}
			require.NoError(t, err, "convert %s failed", image)

			_, err = runWithRetry(t, "check "+image, cfg, func() *exec.Cmd { return exec.Command(nydusify, args("check")...) })
			require.NoError(t, err, "check %s failed", image)
			succeeded.Add(1)
		})
	}
}
