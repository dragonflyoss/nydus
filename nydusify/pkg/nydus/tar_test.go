package nydus

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type bootstrapZeroReader struct{ largest int }

var errBootstrapWrite = errors.New("bootstrap archive write failed")

type bootstrapFailWriter struct{ remaining int }

func (w *bootstrapFailWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		return 0, errBootstrapWrite
	}
	w.remaining -= len(p)
	return len(p), nil
}

func TestStreamingBootstrapTarPropagatesWriteFailures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		limit   int
		message string
	}{
		{"directory header", 0, "bootstrap dir header"},
		{"bootstrap header", 512, "bootstrap file header"},
		{"metadata header", 1024, "blob meta header"},
		{"metadata data", 1536, "write blob meta"},
		{"append header", 2048, "appended file header"},
		{"append data", 2560, "write appended file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tw := tar.NewWriter(&bootstrapFailWriter{remaining: tc.limit})
			err := WriteBootstrapTarFromReader(tw, strings.NewReader(""), 0, []BlobMetaFile{{Name: "blob.blob.meta", Data: []byte("m")}}, []AppendFile{{Name: "state", Data: []byte("s")}})
			require.ErrorIs(t, err, errBootstrapWrite)
			require.ErrorContains(t, err, tc.message)
		})
	}
	tw := tar.NewWriter(io.Discard)
	require.ErrorContains(t, WriteBootstrapTarFromReader(tw, strings.NewReader(""), -1, nil, nil), "bootstrap file header")
}

func (r *bootstrapZeroReader) Read(p []byte) (int, error) {
	if len(p) > r.largest {
		r.largest = len(p)
	}
	clear(p)
	return len(p), nil
}

func TestWriteBootstrapTarFromReaderIsBoundedAndRejectsShortInput(t *testing.T) {
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	input := &bootstrapZeroReader{}
	const size = 2 << 20
	require.NoError(t, WriteBootstrapTarFromReader(tw, input, size, nil, nil))
	require.NoError(t, tw.Close())
	require.LessOrEqual(t, input.largest, 32*1024)
	tr := tar.NewReader(&archive)
	_, err := tr.Next()
	require.NoError(t, err)
	header, err := tr.Next()
	require.NoError(t, err)
	require.Equal(t, BootstrapFileNameInLayer, header.Name)
	require.Equal(t, int64(size), header.Size)
	n, err := io.Copy(io.Discard, tr)
	require.NoError(t, err)
	require.Equal(t, int64(size), n)

	tw = tar.NewWriter(io.Discard)
	require.Error(t, WriteBootstrapTarFromReader(tw, strings.NewReader("short"), 100, nil, nil))
}
