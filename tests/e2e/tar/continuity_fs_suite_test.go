package tar

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/containerd/containerd/v2/pkg/archive"
	"github.com/containerd/continuity/fs/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
)

// TestContinuityFSSuite runs continuity's filesystem suite, which
// containerd's differ is tested with, against nydus: after every step the
// whole tree is written as one layer by containerd's archive.WriteDiff,
// converted by nydus build, and the suite compares the FUSE mount with its
// own copy of the tree.
func TestContinuityFSSuite(t *testing.T) {
	// The suite's steps share the applier's tree, so only the suite as a
	// whole runs alongside the other tests.
	t.Parallel()
	// Root also because the suite creates root-owned trees.
	mount.FUSE{}.Require(t)
	fstest.FSSuite(t, &nydusLayerApplier{t: t})
}

// nydusLayerApplier converts the suite's cumulative tree into a single
// nydus layer after every change.
type nydusLayerApplier struct {
	t    *testing.T
	tree string
}

func (a *nydusLayerApplier) TestContext(ctx context.Context) (context.Context, func(), error) {
	tree, err := os.MkdirTemp("", "fssuite-tree-")
	if err != nil {
		return nil, nil, err
	}
	a.tree = tree
	return ctx, func() { _ = os.RemoveAll(tree) }, nil
}

func (a *nydusLayerApplier) Apply(ctx context.Context, change fstest.Applier) (string, func(), error) {
	if err := change.Apply(a.tree); err != nil {
		return "", nil, err
	}
	var diff bytes.Buffer
	if err := archive.WriteDiff(ctx, &diff, "", a.tree); err != nil {
		return "", nil, err
	}
	// continuity never compares xattrs but lists them, and nydus answers
	// listxattr with EOPNOTSUPP on an image without any, so the first member
	// carries one; the differ itself only writes security.capability.
	var layer bytes.Buffer
	tr, tw := tar.NewReader(&diff), tar.NewWriter(&layer)
	for first := true; ; first = false {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", nil, err
		}
		if first {
			hdr.Format = tar.FormatPAX
			if hdr.PAXRecords == nil {
				hdr.PAXRecords = map[string]string{}
			}
			hdr.PAXRecords["SCHILY.xattr.user.e2e"] = "1"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return "", nil, err
		}
		if _, err := io.Copy(tw, tr); err != nil {
			return "", nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return "", nil, err
	}

	// FSSuite hands Apply no *testing.T, so the step packs and mounts with a
	// stepTB in a goroutine of its own: a failure ends that goroutine and
	// comes back as Apply's error.
	step := &stepTB{t: a.t}
	var root string
	done := make(chan struct{})
	go func() {
		defer close(done)
		work := step.TempDir()
		blob := filepath.Join(work, "layer.blob")
		if err := packLayer(step, &layer, blob, tarLayout{}); err != nil {
			step.Fatalf("%v", err)
		}
		root = mount.Mount(step, mount.FUSE{}, blobImage(work, blob), mount.Options{Mode: mount.Blob}).Root
	}()
	<-done
	if step.Failed() {
		err := step.err()
		step.release()
		return "", nil, err
	}
	return root, step.release, nil
}

// stepTB is the env.TB one FSSuite step mounts with. Failures are recorded
// for Apply to return, FailNow ends only the calling goroutine, and the
// cleanups run when the step releases its mount.
type stepTB struct {
	t *testing.T

	mu       sync.Mutex
	failed   bool
	errs     []string
	cleanups []func()
}

func (s *stepTB) Helper()                         {}
func (s *stepTB) Name() string                    { return s.t.Name() }
func (s *stepTB) Logf(format string, args ...any) { s.t.Logf(format, args...) }

// TempDir hands out directories of the whole test, which outlive the step.
func (s *stepTB) TempDir() string { return s.t.TempDir() }

func (s *stepTB) Errorf(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failed = true
	s.errs = append(s.errs, fmt.Sprintf(format, args...))
}

func (s *stepTB) Fatalf(format string, args ...any) {
	s.Errorf(format, args...)
	s.FailNow()
}

func (s *stepTB) FailNow() {
	s.mu.Lock()
	s.failed = true
	s.mu.Unlock()
	runtime.Goexit()
}

func (s *stepTB) Failed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failed
}

func (s *stepTB) Cleanup(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanups = append(s.cleanups, fn)
}

func (s *stepTB) err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return errors.New(strings.Join(s.errs, "\n"))
}

// release runs the cleanups, last registered first, as testing does.
func (s *stepTB) release() {
	s.mu.Lock()
	cleanups := slices.Clone(s.cleanups)
	s.cleanups = nil
	s.mu.Unlock()
	for _, fn := range slices.Backward(cleanups) {
		fn()
	}
}
