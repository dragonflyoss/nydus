package erofs

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/stretchr/testify/assert"
)

// fsckVersion returns the major and minor version of the fsck.erofs on
// PATH, probed once per process.
var fsckVersion = sync.OnceValues(func() (major, minor int) {
	out, _ := exec.Command("fsck.erofs", "-V").CombinedOutput()
	if m := regexp.MustCompile(`(\d+)\.(\d+)`).FindStringSubmatch(string(out)); m != nil {
		major, _ = strconv.Atoi(m[1])
		minor, _ = strconv.Atoi(m[2])
	}

	return major, minor
})

// FsckDecodes reports whether the installed fsck.erofs can decode images
// compressed with compressor: in-EROFS LZ4 and zstd need erofs-utils 1.8.
func FsckDecodes(t testing.TB, compressor string) bool {
	t.Helper()
	if compressor != "erofs-lz4" && compressor != "erofs-zstd" {
		return true
	}

	env.RequireTool(t, "fsck.erofs")

	major, minor := fsckVersion()
	if major > 1 || (major == 1 && minor >= 8) {
		return true
	}

	t.Logf("fsck.erofs %d.%d cannot decode %s images", major, minor, compressor)

	return false
}

// Fsck validates a bootstrap with erofs-utils. A nydus image is plain
// EROFS, so fsck.erofs is a judge completely independent of the nydus
// reader: it catches encoding bugs the reader happens to tolerate. The
// --device flags come from the image's own device table: the blob
// directory of a merged image holds the blobs of every layer, while a given
// bootstrap references only its own.
func Fsck(t testing.TB, bootstrap, blobDir string) {
	t.Helper()
	fsck := env.RequireTool(t, "fsck.erofs")

	tags, err := DeviceTags(bootstrap)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	args := []string{"--extract"}

	for _, tag := range tags {
		args = append(args, "--device="+filepath.Join(blobDir, tag))
	}

	out := env.Run(t, fsck, append(args, bootstrap)...)
	// fsck.erofs still exits 0 after reporting structural problems such as
	// "wrong dirent name order", so the output has to be scanned as well.
	assert.NotContains(t, out, "filesystem corruption")
}
