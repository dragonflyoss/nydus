package snapshotter

import (
	"path/filepath"
	"testing"
	"time"

	nydussnapshotterv1 "d7y.io/api/v2/pkg/apis/nydussnapshotter/v1"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const preheatTimeout = 2 * time.Minute

func TestPreheat(t *testing.T) {
	t.Parallel()
	n := newNode(t)
	origin := registry.Start(t)
	auth := startBasicAuth(t, origin, "nydus", "secret")
	img := newImage(t, origin, "snapshotter/preheat").on(auth.host)
	n.user, n.password = "nydus", "secret"
	pulled := n.pull(t, img.nydus)
	chainID := n.chainID(t, pulled)
	dir := filepath.Join(n.runDir, "preheat", chainID)
	client := n.preheats(t)

	_, err := client.StatImage(n.ctx, n.statRequest(img.nydus))
	assert.Equal(t, codes.NotFound, status.Code(err), err)

	_, err = client.PreheatImage(n.ctx, n.preheatRequest(img.nydus, "nydus", "wrong"))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	failed := n.waitPreheat(t, client, img.nydus)
	assert.Equal(t, nydussnapshotterv1.ImageState_FAILED, failed.GetState())
	assert.NotEmpty(t, failed.GetBlobs())
	assert.Contains(t, failed.GetDescription(), failed.GetBlobs()[0].GetDigest())
	assert.Contains(t, failed.GetDescription(), "401")
	assert.NotContains(t, failed.GetDescription(), "wrong")
	assert.NoFileExists(t, filepath.Join(dir, "config.yaml"))

	_, err = client.PreheatImage(n.ctx, n.preheatRequest(img.nydus, "nydus", "secret"))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	succeeded := n.waitPreheat(t, client, img.nydus)
	assert.Equal(t, nydussnapshotterv1.ImageState_SUCCEEDED, succeeded.GetState(), succeeded.GetDescription())
	assert.Nil(t, succeeded.Description)

	manifest, err := images.Manifest(n.ctx, n.client.ContentStore(), pulled.Target(), pulled.Platform())
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	var layers, blobs []string
	for _, layer := range manifest.Layers {
		if layer.Annotations[labelNydusBlob] == "true" {
			layers = append(layers, layer.Digest.String())
		}
	}

	var contentLength uint64
	for _, blob := range succeeded.GetBlobs() {
		blobs = append(blobs, blob.GetDigest())
		contentLength += blob.GetContentLength()
		assert.True(t, blob.GetIsFinished(), blob.GetDigest())
		assert.Equal(t, blob.GetContentLength(), blob.GetFinishedContentLength(), blob.GetDigest())
	}
	assert.NotEmpty(t, layers)
	assert.ElementsMatch(t, layers, blobs)
	assert.Positive(t, contentLength)
	assert.NoFileExists(t, filepath.Join(dir, "config.yaml"))
	waitStopped(t, "nydus-preheat-"+chainID+".service", startTimeout)

	gets, challenges := origin.Faults.BlobGets(), auth.challenges.Load()
	assert.Positive(t, gets)
	c := n.start(t, pulled)
	assertFiles(t, c, img)
	assert.Equal(t, gets, origin.Faults.BlobGets())
	assert.Equal(t, challenges, auth.challenges.Load())

	metrics := n.metrics(t)
	assert.Contains(t, metrics, `nydus_snapshotter_preheats_total{result="success"} 1`)
	assert.Contains(t, metrics, `nydus_snapshotter_preheats_total{result="failure"} 1`)
	assert.Contains(t, metrics, "nydus_snapshotter_running_preheats 0")
}

func TestPreheatRejected(t *testing.T) {
	t.Parallel()
	n := newNode(t)
	reg := registry.Start(t)
	img := newImage(t, reg, "snapshotter/preheat-rejected")
	n.pull(t, img.oci)
	client := n.preheats(t)

	_, err := client.PreheatImage(n.ctx, n.preheatRequest(img.oci, "nydus", "secret"))
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), err)

	_, err = client.PreheatImage(n.ctx, n.preheatRequest(img.nydus, "nydus", "secret"))
	assert.Equal(t, codes.NotFound, status.Code(err), err)

	_, err = client.PreheatImage(n.ctx, &nydussnapshotterv1.PreheatImageRequest{Image: img.oci, Namespace: &n.namespace})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), err)

	_, err = client.StatImage(n.ctx, n.statRequest(img.oci))
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), err)

	_, err = client.StatImage(n.ctx, n.statRequest(img.nydus))
	assert.Equal(t, codes.NotFound, status.Code(err), err)

	_, err = client.StatImage(n.ctx, &nydussnapshotterv1.StatImageRequest{Namespace: &n.namespace})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), err)
}

func (n *node) preheats(t *testing.T) nydussnapshotterv1.NydusSnapshotterClient {
	t.Helper()
	conn, err := grpc.NewClient("unix://"+n.snapshotterAddress(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	t.Cleanup(func() { _ = conn.Close() })

	return nydussnapshotterv1.NewNydusSnapshotterClient(conn)
}

func (n *node) preheatRequest(ref, user, password string) *nydussnapshotterv1.PreheatImageRequest {
	return &nydussnapshotterv1.PreheatImageRequest{
		Image:     ref,
		Namespace: &n.namespace,
		Auth: &nydussnapshotterv1.PreheatImageRequest_BasicAuth{
			BasicAuth: &nydussnapshotterv1.BasicAuth{Username: user, Password: password},
		},
	}
}

func (n *node) statRequest(ref string) *nydussnapshotterv1.StatImageRequest {
	return &nydussnapshotterv1.StatImageRequest{Image: ref, Namespace: &n.namespace}
}

func (n *node) waitPreheat(t *testing.T, client nydussnapshotterv1.NydusSnapshotterClient, ref string) *nydussnapshotterv1.StatImageResponse {
	t.Helper()
	var (
		preheat *nydussnapshotterv1.StatImageResponse
		err     error
	)
	if !assert.Eventually(t, func() bool {
		preheat, err = client.StatImage(n.ctx, n.statRequest(ref))
		return err != nil || preheat.GetState() == nydussnapshotterv1.ImageState_SUCCEEDED || preheat.GetState() == nydussnapshotterv1.ImageState_FAILED
	}, preheatTimeout, 100*time.Millisecond) || !assert.NoError(t, err) {
		t.FailNow()
	}

	return preheat
}
