package tar

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/containerd/containerd/v2/pkg/archive"
	"github.com/containerd/continuity/fs/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
)

func TestContinuityFSSuite(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)
	fstest.FSSuite(t, &nydusLayerApplier{t: t})
}

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

	step := &stepTB{TB: a.t}
	var root string
	done := make(chan struct{})

	go func() {
		defer close(done)
		img, err := fixture.PackTar(step, &layer, step.TempDir(), tarLayout{}.compressor, tarLayout{}.chunkSize)
		if err != nil {
			step.Fatal(err)
		}

		root = mount.Mount(step, mount.FUSE{}, img, mount.Options{Mode: mount.Blob}).Root
	}()

	<-done

	if step.Failed() {
		err := step.err()
		step.release()
		return "", nil, err
	}

	return root, step.release, nil
}

type stepTB struct {
	testing.TB
	mu       sync.Mutex
	failed   bool
	errs     []string
	cleanups []func()
}

func (s *stepTB) Errorf(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failed = true
	s.errs = append(s.errs, fmt.Sprintf(format, args...))
}

func (s *stepTB) Error(args ...any) {
	s.Errorf("%s", fmt.Sprint(args...))
}

func (s *stepTB) Fatal(args ...any) {
	s.Fatalf("%s", fmt.Sprint(args...))
}

func (s *stepTB) Skip(args ...any) {
	s.Fatal(args...)
}

func (s *stepTB) Skipf(format string, args ...any) {
	s.Fatalf(format, args...)
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

func (s *stepTB) release() {
	s.mu.Lock()
	cleanups := slices.Clone(s.cleanups)
	s.cleanups = nil

	s.mu.Unlock()

	for _, fn := range slices.Backward(cleanups) {
		fn()
	}
}
