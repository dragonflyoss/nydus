package erofs

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/stretchr/testify/assert"
)

// fsckVersion returns the version of the fsck.erofs on PATH, probed once per
// process: as printed, and as {major, minor, patch, snapshot} so that builds
// compare in order. erofs-utils appends "-g<commit>" to the version of a
// development snapshot past a release, which sets snapshot to 1.
var fsckVersion = sync.OnceValues(func() (text string, version [4]int) {
	out, _ := exec.Command("fsck.erofs", "-V").CombinedOutput()

	m := regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?(-g[0-9a-f]+)?`).FindStringSubmatch(string(out))
	if m == nil {
		return "", version
	}

	for i := range 3 {
		version[i], _ = strconv.Atoi(m[i+1])
	}

	if m[4] != "" {
		version[3] = 1
	}

	return m[0], version
})

// FsckDecodes reports whether the installed fsck.erofs can decode images
// compressed with compressor. In-EROFS LZ4 and zstd pclusters live on an
// extra device and are addressed in the mapped block space; fsck.erofs
// resolves such an address to its device only since erofs-utils c65a25f
// ("add missing device_id derivation for flattened devices"), which follows
// the 1.9.4 release: earlier versions read the bootstrap instead and report
// corruption. Without such a fsck.erofs the check is left out locally, and
// the test fails under CI.
func FsckDecodes(t testing.TB, compressor string) bool {
	t.Helper()
	if compressor != "erofs-lz4" && compressor != "erofs-zstd" {
		return true
	}

	env.LookPath(t, "fsck.erofs")

	text, version := fsckVersion()
	if slices.Compare(version[:], []int{1, 9, 4, 0}) > 0 {
		return true
	}

	env.Omitf(t, "fsck.erofs %s cannot decode %s images, erofs-utils newer than 1.9.4 is required", text, compressor)

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
	fsck := env.LookPath(t, "fsck.erofs")

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
