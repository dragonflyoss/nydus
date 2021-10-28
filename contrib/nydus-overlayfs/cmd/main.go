package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"
)

const (
	extraOptionKey = "extraoption="
)

var (
	Version   = "development"
	BuildTime = "unknown"
)

/*
   containerd run fuse.mount format: nydus-overlayfs overlay /tmp/ctd-volume107067851
   -o lowerdir=/foo/lower2:/foo/lower1,upperdir=/foo/upper,workdir=/foo/work,extraoption={...},dev,suid]
*/
type mountArgs struct {
	fsType  string
	target  string
	options []string
}

func parseArgs(args []string) (*mountArgs, error) {
	margs := &mountArgs{
		fsType: args[0],
		target: args[1],
	}
	if margs.fsType != "overlay" {
		return nil, errors.New("fsType only support overlay")
	}
	if len(margs.target) == 0 {
		return nil, errors.New("target can not be empty")
	}
	if args[2] == "-o" && len(args[3]) != 0 {
		for _, opt := range strings.Split(args[3], ",") {
			if strings.HasPrefix(opt, extraOptionKey) {
				// filter extraoption
				continue
			}
			margs.options = append(margs.options, opt)
		}
	}
	if len(margs.options) == 0 {
		return nil, errors.New("options can not be empty")
	}
	return margs, nil
}

func parseOptions(options []string) (int, string) {
	flagsTable := map[string]int{
		"async":         unix.MS_SYNCHRONOUS,
		"atime":         unix.MS_NOATIME,
		"bind":          unix.MS_BIND,
		"defaults":      0,
		"dev":           unix.MS_NODEV,
		"diratime":      unix.MS_NODIRATIME,
		"dirsync":       unix.MS_DIRSYNC,
		"exec":          unix.MS_NOEXEC,
		"mand":          unix.MS_MANDLOCK,
		"noatime":       unix.MS_NOATIME,
		"nodev":         unix.MS_NODEV,
		"nodiratime":    unix.MS_NODIRATIME,
		"noexec":        unix.MS_NOEXEC,
		"nomand":        unix.MS_MANDLOCK,
		"norelatime":    unix.MS_RELATIME,
		"nostrictatime": unix.MS_STRICTATIME,
		"nosuid":        unix.MS_NOSUID,
		"rbind":         unix.MS_BIND | unix.MS_REC,
		"relatime":      unix.MS_RELATIME,
		"remount":       unix.MS_REMOUNT,
		"ro":            unix.MS_RDONLY,
		"rw":            unix.MS_RDONLY,
		"strictatime":   unix.MS_STRICTATIME,
		"suid":          unix.MS_NOSUID,
		"sync":          unix.MS_SYNCHRONOUS,
	}
	var (
		flags int
		data  []string
	)
	for _, o := range options {
		if f, exist := flagsTable[o]; exist {
			flags |= f
		} else {
			data = append(data, o)
		}
	}
	return flags, strings.Join(data, ",")
}

func run(args cli.Args) error {
	margs, err := parseArgs(args.Slice())
	if err != nil {
		return errors.Wrap(err, "parseArgs err")
	}

	log.Printf("domount info: %v\n", margs)

	flags, data := parseOptions(margs.options)
	err = syscall.Mount(margs.fsType, margs.target, margs.fsType, uintptr(flags), data)
	if err != nil {
		return errors.Wrap(err, "doMount err")
	}
	return nil
}

func main() {
	app := &cli.App{
		Name:      "NydusOverlayfs",
		Usage:     "Binary for containerd mount helper to do mount operation in nydus env",
		Version:   fmt.Sprintf("%s.%s", Version, BuildTime),
		UsageText: "[Usage]: ./nydus-overlayfs overlay <target> -o <options>",
		Action: func(c *cli.Context) error {
			return run(c.Args())
		},
		Before: func(c *cli.Context) error {
			if c.NArg() != 4 {
				cli.ShowAppHelpAndExit(c, 1)
			}
			return nil
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
	os.Exit(0)
}
