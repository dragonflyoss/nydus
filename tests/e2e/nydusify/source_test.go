package nydusify

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/stretchr/testify/assert"
)

type source struct {
	name string
	dirs []string
	want []fstest.Entry
}

func newSource(t testing.TB, name string, dirs ...string) source {
	t.Helper()
	views := make([][]fstest.Entry, len(dirs))

	for i, dir := range dirs {
		views[i] = fstest.TarView(fstest.ScanSource(t, dir))
	}

	return source{name: name, dirs: dirs, want: fstest.Overlay(views...)}
}

func (s source) compare() fstest.CompareOptions {
	return fstest.CompareOptions{Nlink: len(s.dirs) == 1}
}

func corpusSources(t testing.TB) []source {
	t.Helper()
	return []source{
		newSource(t, "single", fixture.Corpus(t, fixture.Standard)),
		newSource(t, "multi", fixture.LayerDirs(t)...),
	}
}

func inputTree(t testing.TB, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()

	for name, data := range files {
		path := filepath.Join(dir, name)
		if !assert.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755)) {
			t.FailNow()
		}
		if !assert.NoError(t, os.WriteFile(path, []byte(data), 0o640)) {
			t.FailNow()
		}

		stamp := time.Unix(1700000000, 0)
		assert.NoError(t, os.Chtimes(path, stamp, stamp))
	}

	return dir
}
