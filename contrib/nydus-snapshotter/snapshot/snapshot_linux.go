// +build linux

package snapshot

import "github.com/containerd/continuity/fs"

func getSupportsDType(dir string) (bool, error){
	return fs.SupportsDType(dir)
}
