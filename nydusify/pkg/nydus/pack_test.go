package nydus

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeBuilder(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "builder")
	script := "#!/bin/sh\nset -eu\nshift\nsource=$1\nshift\nblob=\ntype=\nwhile [ $# -gt 0 ]; do\ncase $1 in\n--blob) blob=$2;;\n--source-type) type=$2;;\nesac\nshift 2\ndone\n" + body
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPackStreamsTarWithoutExtraction(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	work := t.TempDir()
	var output bytes.Buffer
	writer, err := Pack(ctx, &output, PackOption{WorkDir: work, BuilderPath: fakeBuilder(t, "test \"$type\" = tar\ncat \"$source\" > \"$blob\"\n")})
	if err != nil {
		t.Fatal(err)
	}
	member := tarReg("f")
	member.Size = 180000
	if _, err := writer.Write(encodeTar(t, member)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(&output)
	hdr, err := tr.Next()
	if err != nil || hdr.Name != "f" {
		t.Fatalf("normalized stream lost the member: %v %v", hdr, err)
	}
	if got, err := io.ReadAll(tr); err != nil || !bytes.Equal(got, bytes.Repeat([]byte("x"), int(member.Size))) {
		t.Fatal("stream changed")
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(work)
	if err != nil || len(entries) != 0 {
		t.Fatalf("scratch files leaked: %v %v", entries, err)
	}
}

func TestPackUnblocksWhenBuilderExitsEarly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	writer, err := Pack(ctx, io.Discard, PackOption{BuilderPath: fakeBuilder(t, "echo rejected >&2\nexit 7\n"), WorkDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	// Write past any pipe's capacity so the write must see the builder go.
	hdr := tarReg("f")
	hdr.Size = 16 << 20
	if _, err := writer.Write(encodeTar(t, hdr)); err == nil {
		t.Fatal("expected failed input stream")
	}
	if err := writer.Close(); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("missing builder error: %v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("builder exit did not unblock the input")
	}
}

type failedDestination struct{ err error }

func (dest failedDestination) Write([]byte) (int, error) { return 0, dest.err }

func TestPackStopsOnDestinationFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	expected := errors.New("destination failed")
	writer, err := Pack(ctx, failedDestination{expected}, PackOption{BuilderPath: fakeBuilder(t, "exec cat \"$source\" > \"$blob\"\n"), WorkDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = writer.Write(make([]byte, 1<<20))
	if err := writer.Close(); !errors.Is(err, expected) {
		t.Fatalf("expected destination error: %v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("destination failure hung")
	}
}

func TestPackCancellationUnblocksInput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	writer, err := Pack(ctx, io.Discard, PackOption{BuilderPath: fakeBuilder(t, "exec cat \"$source\" > \"$blob\"\n"), WorkDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := writer.Write([]byte("x")); err == nil {
		t.Fatal("expected canceled stream")
	}
	if err := writer.Close(); err == nil {
		t.Fatal("expected canceled build")
	}
}
