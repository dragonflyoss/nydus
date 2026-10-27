package oracle

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestReadDirents(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for i := 0; i < 40; i++ {
		name := fmt.Sprintf("%02d%s", i, strings.Repeat("x", i%3*100))
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), nil, 0o600))
	}
	for _, size := range []int{256, 512, 4096} {
		entries := ReadDirents(t, dir, size)
		require.Len(t, entries, 42)
		seen := map[string]bool{}
		for _, entry := range entries {
			require.False(t, seen[entry.Name], "duplicate %q", entry.Name)
			seen[entry.Name] = true
			var st unix.Stat_t
			require.NoError(t, unix.Lstat(filepath.Join(dir, entry.Name), &st))
			require.Equal(t, st.Ino, entry.Ino)
			if entry.Name != "." && entry.Name != ".." {
				require.Equal(t, uint8(unix.DT_REG), entry.Type)
			}
		}
	}
}
