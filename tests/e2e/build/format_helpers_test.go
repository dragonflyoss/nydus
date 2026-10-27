package build

import (
	"context"
	"encoding/binary"
	"hash/crc32"
	"os/exec"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/stretchr/testify/require"
)

var formatCRC = crc32.MakeTable(crc32.Castagnoli)

func sealFormatRegion(data []byte) {
	clear(data[16:20])
	binary.LittleEndian.PutUint32(data[16:20], crc32.Checksum(data, formatCRC))
}

func formatCommand(t env.TB, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, env.Nydus(t), args...).CombinedOutput()
	require.NoError(t, ctx.Err(), "image parser hung: %s", out)
	if err != nil {
		var exit *exec.ExitError
		require.ErrorAs(t, err, &exit, "%s", out)
		require.Positive(t, exit.ExitCode(), "image parser died by signal: %s", out)
		require.NotEqual(t, 101, exit.ExitCode(), "image parser panicked: %s", out)
	}
	return out, err
}
