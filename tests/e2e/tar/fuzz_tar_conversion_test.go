package tar

import (
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
)

// FuzzTarConversion runs checkTarConversion on arbitrary bytes. Without
// -fuzz it replays the seeds, small random layers whole and cut in half;
// with it, run as root:
// go test -run '^$' -fuzz FuzzTarConversion -fuzztime 10m ./tar
func FuzzTarConversion(f *testing.F) {
	for i := range 4 {
		data := randomTar(newTarRand(3000+uint64(i)), 16<<10)
		f.Add(data)
		f.Add(data[:len(data)/2])
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		mount.FUSE{}.Require(t)
		checkTarConversion(t, data, tarLayout{})
	})
}
