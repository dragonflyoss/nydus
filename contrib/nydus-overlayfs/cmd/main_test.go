package main

import (
	stderrors "errors"
	"reflect"
	"strings"
	"testing"

	cli "github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"
)

type fakeArgs []string

func (f fakeArgs) Get(n int) string {
	if n < 0 || n >= len(f) {
		return ""
	}

	return f[n]
}

func (f fakeArgs) First() string {
	return f.Get(0)
}

func (f fakeArgs) Len() int {
	return len(f)
}

func (f fakeArgs) Present() bool {
	return len(f) > 0
}

func (f fakeArgs) Slice() []string {
	return append([]string(nil), f...)
}

func (f fakeArgs) Tail() []string {
	if len(f) <= 1 {
		return nil
	}

	return append([]string(nil), f[1:]...)
}

var _ cli.Args = fakeArgs{}

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantOptions []string
		wantErr     string
	}{
		{
			name: "filters containerd passthrough options",
			args: []string{
				"overlay",
				"/merged",
				"-o",
				"lowerdir=/lower,extraoption={\"trace\":true},upperdir=/upper,io.katacontainers.volume={\"device\":\"vdb\"},workdir=/work,nodev",
			},
			wantOptions: []string{"lowerdir=/lower", "upperdir=/upper", "workdir=/work", "nodev"},
		},
		{
			name:    "rejects non overlay fs type",
			args:    []string{"ext4", "/merged", "-o", "lowerdir=/lower"},
			wantErr: "fsType only support overlay",
		},
		{
			name:    "rejects empty target",
			args:    []string{"overlay", "", "-o", "lowerdir=/lower"},
			wantErr: "target can not be empty",
		},
		{
			name:    "rejects missing usable options",
			args:    []string{"overlay", "/merged", "-o", "extraoption={\"trace\":true}"},
			wantErr: "options can not be empty",
		},
		{
			name:    "rejects missing option flag",
			args:    []string{"overlay", "/merged", "--", "lowerdir=/lower"},
			wantErr: "options can not be empty",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := parseArgs(tc.args)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("parseArgs returned error: %v", err)
			}
			if parsed.fsType != "overlay" {
				t.Fatalf("unexpected fsType %q", parsed.fsType)
			}
			if parsed.target != "/merged" {
				t.Fatalf("unexpected target %q", parsed.target)
			}
			if !reflect.DeepEqual(parsed.options, tc.wantOptions) {
				t.Fatalf("unexpected options %v", parsed.options)
			}
		})
	}
}

func TestParseOptions(t *testing.T) {
	flags, data := parseOptions([]string{"rbind", "remount", "nosuid", "lowerdir=/lower", "upperdir=/upper"})
	wantFlags := unix.MS_BIND | unix.MS_REC | unix.MS_REMOUNT | unix.MS_NOSUID
	if flags != wantFlags {
		t.Fatalf("unexpected flags %d, want %d", flags, wantFlags)
	}
	if data != "lowerdir=/lower,upperdir=/upper" {
		t.Fatalf("unexpected data %q", data)
	}

	flags, data = parseOptions(nil)
	if flags != 0 {
		t.Fatalf("unexpected empty flags %d", flags)
	}
	if data != "" {
		t.Fatalf("unexpected empty data %q", data)
	}
}

func TestRun(t *testing.T) {
	oldMount := mountFn
	defer func() {
		mountFn = oldMount
	}()

	t.Run("wraps parse errors", func(t *testing.T) {
		mountFn = func(source, target, fstype string, flags uintptr, data string) error {
			t.Fatal("mountFn should not be called when arguments are invalid")
			return nil
		}

		err := run(fakeArgs{"ext4", "/merged", "-o", "lowerdir=/lower"})
		if err == nil || !strings.Contains(err.Error(), "parseArgs err") {
			t.Fatalf("expected wrapped parse error, got %v", err)
		}
	})

	t.Run("passes parsed mount parameters", func(t *testing.T) {
		var (
			gotSource string
			gotTarget string
			gotFsType string
			gotFlags  uintptr
			gotData   string
		)
		mountFn = func(source, target, fstype string, flags uintptr, data string) error {
			gotSource = source
			gotTarget = target
			gotFsType = fstype
			gotFlags = flags
			gotData = data
			return nil
		}

		err := run(fakeArgs{"overlay", "/merged", "-o", "lowerdir=/lower,upperdir=/upper,workdir=/work,nosuid"})
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
		if gotSource != "overlay" || gotTarget != "/merged" || gotFsType != "overlay" {
			t.Fatalf("unexpected mount call %q %q %q", gotSource, gotTarget, gotFsType)
		}
		if gotFlags != uintptr(unix.MS_NOSUID) {
			t.Fatalf("unexpected flags %d", gotFlags)
		}
		if gotData != "lowerdir=/lower,upperdir=/upper,workdir=/work" {
			t.Fatalf("unexpected data %q", gotData)
		}
	})

	t.Run("wraps mount failures", func(t *testing.T) {
		mountFn = func(source, target, fstype string, flags uintptr, data string) error {
			return stderrors.New("mount failed")
		}

		err := run(fakeArgs{"overlay", "/merged", "-o", "lowerdir=/lower,upperdir=/upper,workdir=/work"})
		if err == nil || !strings.Contains(err.Error(), "doMount err") {
			t.Fatalf("expected wrapped mount error, got %v", err)
		}
	})
}
