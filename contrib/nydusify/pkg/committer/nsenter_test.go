package committer

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildCommandNoTarget(t *testing.T) {
	cmd, err := (&Config{}).buildCommand(context.Background())
	require.ErrorContains(t, err, "target must be specified")
	require.Nil(t, cmd)
}

func TestBuildCommandMinimalValid(t *testing.T) {
	cmd, err := (&Config{Target: 1234}).buildCommand(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"nsenter", "--target", "1234"}, cmd.Args)
}

func TestBuildCommandNamespacesWithoutFiles(t *testing.T) {
	cmd, err := (&Config{
		Target: 5678,
		Cgroup: true,
		IPC:    true,
		Mount:  true,
		Net:    true,
		PID:    true,
		User:   true,
		UTS:    true,
	}).buildCommand(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{
		"nsenter",
		"--target", "5678",
		"--cgroup",
		"--ipc",
		"--mount",
		"--net",
		"--pid",
		"--user",
		"--uts",
	}, cmd.Args)
}

func TestBuildCommandNamespacesWithFiles(t *testing.T) {
	cmd, err := (&Config{
		Target:     5678,
		Cgroup:     true,
		CgroupFile: "/proc/1234/ns/cgroup",
		IPC:        true,
		IPCFile:    "/proc/1234/ns/ipc",
		Mount:      true,
		MountFile:  "/proc/1234/ns/mnt",
		Net:        true,
		NetFile:    "/proc/1234/ns/net",
		PID:        true,
		PIDFile:    "/proc/1234/ns/pid",
		User:       true,
		UserFile:   "/proc/1234/ns/user",
		UTS:        true,
		UTSFile:    "/proc/1234/ns/uts",
	}).buildCommand(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{
		"nsenter",
		"--target", "5678",
		"--cgroup=/proc/1234/ns/cgroup",
		"--ip=/proc/1234/ns/ipc",
		"--mount=/proc/1234/ns/mnt",
		"--net=/proc/1234/ns/net",
		"--pid=/proc/1234/ns/pid",
		"--user=/proc/1234/ns/user",
		"--uts=/proc/1234/ns/uts",
	}, cmd.Args)
}

func TestBuildCommandCredentialAndDirectoryFlags(t *testing.T) {
	cmd, err := (&Config{
		Target:              2000,
		FollowContext:       true,
		GID:                 1002,
		NoFork:              true,
		PreserveCredentials: true,
		RootDirectory:       "/new/root",
		UID:                 1001,
		WorkingDirectory:    "/tmp/work",
	}).buildCommand(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{
		"nsenter",
		"--target", "2000",
		"--follow-context",
		"--setgid", "1002",
		"--no-fork",
		"--preserve-credentials",
		"--root", "/new/root",
		"--setuid", "1001",
		"--wd", "/tmp/work",
	}, cmd.Args)
}

func TestBuildCommandIgnoresZeroValues(t *testing.T) {
	cmd, err := (&Config{
		Target: 5000,
		UID:    0,
		GID:    0,
	}).buildCommand(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"nsenter", "--target", "5000"}, cmd.Args)
}
