// Ported from go-nsenter project, copyright The go-nsenter Authors.
// https://github.com/Devatoria/go-nsenter

package committer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"time"
)

// Config is the nsenter configuration used to generate
// nsenter command
type Config struct {
	Cgroup              bool   // Enter cgroup namespace
	CgroupFile          string // Cgroup namespace location, default to /proc/PID/ns/cgroup
	FollowContext       bool   // Set SELinux security context
	GID                 int    // GID to use to execute given program
	IPC                 bool   // Enter IPC namespace
	IPCFile             string // IPC namespace location, default to /proc/PID/ns/ipc
	Mount               bool   // Enter mount namespace
	MountFile           string // Mount namespace location, default to /proc/PID/ns/mnt
	Net                 bool   // Enter network namespace
	NetFile             string // Network namespace location, default to /proc/PID/ns/net
	NoFork              bool   // Do not fork before executing the specified program
	PID                 bool   // Enter PID namespace
	PIDFile             string // PID namespace location, default to /proc/PID/ns/pid
	PreserveCredentials bool   // Preserve current UID/GID when entering namespaces
	RootDirectory       string // Set the root directory, default to target process root directory
	Target              int    // Target PID (required)
	UID                 int    // UID to use to execute given program
	User                bool   // Enter user namespace
	UserFile            string // User namespace location, default to /proc/PID/ns/user
	UTS                 bool   // Enter UTS namespace
	UTSFile             string // UTS namespace location, default to /proc/PID/ns/uts
	WorkingDirectory    string // Set the working directory, default to target process working directory
}

// Execute executes the given command with a default background context
func (c *Config) Execute(writer io.Writer, program string, args ...string) (string, error) {
	return c.ExecuteContext(context.Background(), writer, program, args...)
}

// ExecuteContext the given program using the given nsenter configuration and given context
// and return stdout/stderr or an error if command has failed
func (c *Config) ExecuteContext(ctx context.Context, writer io.Writer, program string, args ...string) (string, error) {
	cmd, err := c.buildCommand(ctx)
	if err != nil {
		return "", fmt.Errorf("Error while building command: %v", err)
	}

	// Prepare command
	var srderr bytes.Buffer
	rc, err := cmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("Open stdout pipe: %v", err)
	}
	defer rc.Close()

	cmd.Stderr = &srderr
	cmd.Args = append(cmd.Args, program)
	cmd.Args = append(cmd.Args, args...)

	if err := cmd.Start(); err != nil {
		return srderr.String(), err
	}

	// HACK: we can't wait rc.Close happen automatically when process
	// exits, so must check process state and call rc.Close() by manually.
	go func() {
		for {
			time.Sleep(time.Second * 1)
			if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
				rc.Close()
				break
			}
		}
	}()

	if _, err := io.Copy(writer, rc); err != nil {
		return srderr.String(), err
	}

	return srderr.String(), cmd.Wait()
}

func (c *Config) buildCommand(ctx context.Context) (*exec.Cmd, error) {
	if c.Target == 0 {
		return nil, fmt.Errorf("Target must be specified")
	}

	var args []string
	args = append(args, "--target", strconv.Itoa(c.Target))

	if c.Cgroup {
		if c.CgroupFile != "" {
			args = append(args, fmt.Sprintf("--cgroup=%s", c.CgroupFile))
		} else {
			args = append(args, "--cgroup")
		}
	}

	if c.FollowContext {
		args = append(args, "--follow-context")
	}

	if c.GID != 0 {
		args = append(args, "--setgid", strconv.Itoa(c.GID))
	}

	if c.IPC {
		if c.IPCFile != "" {
			args = append(args, fmt.Sprintf("--ip=%s", c.IPCFile))
		} else {
			args = append(args, "--ipc")
		}
	}

	if c.Mount {
		if c.MountFile != "" {
			args = append(args, fmt.Sprintf("--mount=%s", c.MountFile))
		} else {
			args = append(args, "--mount")
		}
	}

	if c.Net {
		if c.NetFile != "" {
			args = append(args, fmt.Sprintf("--net=%s", c.NetFile))
		} else {
			args = append(args, "--net")
		}
	}

	if c.NoFork {
		args = append(args, "--no-fork")
	}

	if c.PID {
		if c.PIDFile != "" {
			args = append(args, fmt.Sprintf("--pid=%s", c.PIDFile))
		} else {
			args = append(args, "--pid")
		}
	}

	if c.PreserveCredentials {
		args = append(args, "--preserve-credentials")
	}

	if c.RootDirectory != "" {
		args = append(args, "--root", c.RootDirectory)
	}

	if c.UID != 0 {
		args = append(args, "--setuid", strconv.Itoa(c.UID))
	}

	if c.User {
		if c.UserFile != "" {
			args = append(args, fmt.Sprintf("--user=%s", c.UserFile))
		} else {
			args = append(args, "--user")
		}
	}

	if c.UTS {
		if c.UTSFile != "" {
			args = append(args, fmt.Sprintf("--uts=%s", c.UTSFile))
		} else {
			args = append(args, "--uts")
		}
	}

	if c.WorkingDirectory != "" {
		args = append(args, "--wd", c.WorkingDirectory)
	}

	cmd := exec.CommandContext(ctx, "nsenter", args...)

	return cmd, nil
}
