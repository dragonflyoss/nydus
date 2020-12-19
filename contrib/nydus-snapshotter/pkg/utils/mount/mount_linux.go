// +build linux

package mount

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type Mounter struct {

}

func (m *Mounter) Umount(target string) error {
	if isNotMountPoint, _ := m.IsLikelyNotMountPoint(target); isNotMountPoint {
		return nil
	}
	return syscall.Unmount(target, syscall.MNT_FORCE)
}

func (m *Mounter) IsLikelyNotMountPoint(file string) (bool, error) {
	stat, err := os.Stat(file)
	if err != nil {
		return true, err
	}
	rootStat, err := os.Stat(filepath.Dir(strings.TrimSuffix(file, "/")))
	if err != nil {
		return true, err
	}
	// If the directory has a different device as parent, then it is a mountpoint.
	if stat.Sys().(*syscall.Stat_t).Dev != rootStat.Sys().(*syscall.Stat_t).Dev {
		return false, nil
	}

	return true, nil
}



