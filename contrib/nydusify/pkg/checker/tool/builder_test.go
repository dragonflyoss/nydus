package tool

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewBuilder(t *testing.T) {
	builder := NewBuilder("/usr/bin/nydus-image")
	require.NotNil(t, builder)
	require.Equal(t, "/usr/bin/nydus-image", builder.binaryPath)
	require.Equal(t, os.Stdout, builder.stdout)
	require.Equal(t, os.Stderr, builder.stderr)
}

func TestBuilderCheck(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		workDir := t.TempDir()
		argFile := filepath.Join(workDir, "args.txt")
		scriptPath := filepath.Join(workDir, "builder.sh")
		script := "#!/bin/sh\nprintf '%s\n' \"$@\" > \"" + argFile + "\"\n"
		require.NoError(t, os.WriteFile(scriptPath, []byte(script), 0755))

		var stdout bytes.Buffer
		var stderr bytes.Buffer
		builder := NewBuilder(scriptPath)
		builder.stdout = &stdout
		builder.stderr = &stderr

		err := builder.Check(BuilderOption{
			BootstrapPath:   "/tmp/bootstrap",
			DebugOutputPath: "/tmp/debug.json",
		})
		require.NoError(t, err)

		args, err := os.ReadFile(argFile)
		require.NoError(t, err)
		require.Equal(t, "check\n--log-level\nwarn\n--output-json\n/tmp/debug.json\n--bootstrap\n/tmp/bootstrap\n", string(args))
	})

	t.Run("command failed", func(t *testing.T) {
		workDir := t.TempDir()
		scriptPath := filepath.Join(workDir, "builder.sh")
		script := "#!/bin/sh\nexit 1\n"
		require.NoError(t, os.WriteFile(scriptPath, []byte(script), 0755))

		builder := NewBuilder(scriptPath)
		err := builder.Check(BuilderOption{})
		require.Error(t, err)
	})
}
