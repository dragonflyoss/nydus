package provider

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestPipeBlobStream(t *testing.T) {
	store := NewMemoryContentStore().(*memoryContentStore)
	ctx := context.Background()

	data := bytes.Repeat([]byte("nydus"), 1024*1024) // 5MB
	expectedDigest := digest.FromBytes(data)
	expectedSize := int64(len(data))

	// 写端
	writer, err := store.Writer(ctx)
	if err != nil {
		t.Fatalf("Writer error: %v", err)
	}
	nw, err := writer.Write(data)
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if nw != len(data) {
		t.Fatalf("Write size mismatch: %d != %d", nw, len(data))
	}
	if err := writer.Commit(ctx, int64(nw), expectedDigest); err != nil {
		t.Fatalf("Commit error: %v", err)
	}
	writer.Close()

	// 读端
	readBuf := make([]byte, len(data))
	desc := ocispec.Descriptor{Digest: expectedDigest}
	readerAt, err := store.ReaderAt(ctx, desc)
	if err != nil {
		t.Fatalf("ReaderAt error: %v", err)
	}
	defer readerAt.Close()

	n, err := readerAt.ReadAt(readBuf, 0)
	if err != nil && err != io.EOF {
		t.Fatalf("ReadAt error: %v", err)
	}
	if int64(n) != expectedSize {
		t.Fatalf("Read size mismatch: %d != %d", n, expectedSize)
	}
	if !bytes.Equal(data, readBuf) {
		t.Fatalf("Data mismatch")
	}
}
