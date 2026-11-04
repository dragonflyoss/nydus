package bench

import (
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/stretchr/testify/assert"
)

func BenchmarkMount(b *testing.B) {
	env.MustHaveRoot(b)
	fio := env.LookPath(b, "fio")
	work := env.WorkDir(b)
	warm := env.Bool(b, "NYDUS_E2E_BENCH_WARM", false)
	fileioNoWarm := env.Bool(b, "NYDUS_E2E_BENCH_FILEIO_NOWARM", false)
	smallFiles := env.Int(b, "NYDUS_E2E_BENCH_SMALL_FILE_COUNT", 10000)
	if !assert.Positive(b, smallFiles) {
		b.FailNow()
	}

	src := filepath.Join(work, "corpus")
	makePerfCorpus(b, src, smallFiles)
	img := fixture.BuildImage(b, work, src, imageLayout)

	v2 := buildV2Image(b, work, src)
	for _, m := range modes(b, env.Nydus(b), img, v2, fileioNoWarm) {
		b.Run(m.name, func(b *testing.B) {
			if m.skip != "" {
				env.Skipf(b, "benchmark mode %s unavailable: %s", m.name, m.skip)
			}
			sums := map[string]float64{}

			for b.Loop() {
				for unit, value := range m.runMode(b, fio, warm, smallFiles).metrics() {
					sums[unit] += value
				}
			}

			b.ReportMetric(0, "ns/op")

			for unit, sum := range sums {
				b.ReportMetric(sum/float64(b.N), unit)
			}
		})
	}
}
