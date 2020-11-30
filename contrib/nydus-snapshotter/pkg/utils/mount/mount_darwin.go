// +build !linux

package mount

type Mounter struct {
}

func (m *Mounter) Umount(target string) error {
	return nil
}

func (m *Mounter) IsLikelyNotMountPoint(file string) (bool, error) {
	return true, nil
}
