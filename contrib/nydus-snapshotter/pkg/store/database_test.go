package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/daemon"
	"github.com/stretchr/testify/require"
)

func Test_daemon(t *testing.T) {
	rootDir := "testdata/snapshot"
	err := os.MkdirAll(rootDir, 0755)
	require.Nil(t, err)
	defer func() {
		_ = os.RemoveAll(rootDir)
	}()

	db, err := NewDatabase(rootDir)
	require.Nil(t, err)

	ctx := context.TODO()
	// Add daemons
	d1 := daemon.Daemon{ID: "d1"}
	d2 := daemon.Daemon{ID: "d2"}
	d3 := daemon.Daemon{ID: "d3"}
	err = db.SaveDaemon(ctx, &d1)
	require.Nil(t, err)
	err = db.SaveDaemon(ctx, &d2)
	require.Nil(t, err)
	db.SaveDaemon(ctx, &d3)
	require.Nil(t, err)
	// duplicate daemon id should fail
	err = db.SaveDaemon(ctx, &d1)
	require.Error(t, err)

	// Delete one daemon
	err = db.DeleteDaemon(ctx, "d2")
	require.Nil(t, err)

	// Check records
	ids := make(map[string]string)
	err = db.WalkDaemons(ctx, func(info *daemon.Daemon) error {
		ids[info.ID] = ""
		return nil
	})
	_, ok := ids["d1"]
	require.Equal(t, ok, true)
	_, ok = ids["d2"]
	require.Equal(t, ok, false)
	_, ok = ids["d3"]
	require.Equal(t, ok, true)

	// Cleanup records
	err = db.Cleanup(ctx)
	require.Nil(t, err)
	ids2 := make([]string, 0)
	err = db.WalkDaemons(ctx, func(info *daemon.Daemon) error {
		ids2 = append(ids2, info.ID)
		return nil
	})
	require.Nil(t, err)
	require.Equal(t, len(ids2), 0)
}

func Test_cache(t *testing.T) {
	rootDir := "testdata/snapshot"
	err := os.MkdirAll(rootDir, 0755)
	require.Nil(t, err)
	defer func() {
		_ = os.RemoveAll(rootDir)
	}()

	db, err := NewDatabase(rootDir)
	require.Nil(t, err)
	tests := []struct {
		imageID string
		blobs   []string
	}{
		{
			imageID: "snapshot-01",
			blobs:   []string{"blob-01", "blob-02", "blob-03"},
		},
		{
			imageID: "snapshot-02",
			blobs:   []string{"blob-02", "blob-03", "blob-04"},
		},
	}
	for _, tt := range tests {
		ss := &Snapshot{
			ImageID:  tt.imageID,
			Blobs:    tt.blobs,
			CreateAt: time.Now(),
			UpdateAt: time.Now(),
		}
		err := db.addSnapshot(tt.imageID, ss)
		if err != nil {
			t.Fatalf("add snapshot err, %v", err)
		}
		for _, id := range tt.blobs {
			blob := &Blob{
				CreateAt: time.Now(),
				UpdateAt: time.Now(),
			}
			if err := db.addBlob(id, blob); err != nil {
				t.Fatalf("add blob err, %v", err)
			}
		}
		time.Sleep(time.Second * 5)
	}
	if err := db.delSnapshot("snapshot-01"); err != nil {
		t.Fatalf("del snapshot err, %v\n", err)
	}
	blobs, err := db.getUnusedBlobs()
	if err != nil {
		t.Fatalf("get unused blob err, %v\n", err)
	}
	if len(blobs) != 1 || blobs[0] != "blob-01" {
		t.Fatalf("test cache failed, blobs: %v", blobs)
	}
}
