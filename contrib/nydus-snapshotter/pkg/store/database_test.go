package store

import (
	"context"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/daemon"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func Test_database(t *testing.T) {
	rootDir := "testdata/snapshot"
	err := os.MkdirAll(rootDir, 0755)
	require.Nil(t, err)
	defer func() {
		_ = os.RemoveAll(rootDir)
	}()

	dbFile := filepath.Join(rootDir, databaseFileName)
	db, err := NewDatabase(dbFile)
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
