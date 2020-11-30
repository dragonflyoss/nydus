// +build !linux

package snapshot

func getSupportsDType(dir string) (bool, error){
	return true, nil
}

