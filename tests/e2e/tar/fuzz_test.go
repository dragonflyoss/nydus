package tar

import (
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
)

func FuzzTarConversion(f *testing.F) {
	for i := range 4 {
		data := randomTar(newTarRand(3000+uint64(i)), 16<<10)
		f.Add(data)
		f.Add(data[:len(data)/2])
	}

	mount.FUSE{}.Require(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		(tarLayout{}).checkTarConversion(t, data)
	})
}
