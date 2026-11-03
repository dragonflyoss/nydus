package main

import (
	"io"
	"os"
	"path/filepath"
)

// Save only after publishing succeeds. Open the source before creating the
// destination so exporting onto the input path is safe as well.
func saveBootstrap(path, source string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	var mode os.FileMode
	preserveMode := false
	if info, err := os.Stat(path); err == nil {
		mode, preserveMode = info.Mode().Perm(), true
	} else if !os.IsNotExist(err) {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".image.boot-*")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer func() { _ = os.Remove(temp) }()
	defer func() { _ = file.Close() }()
	if _, err := io.Copy(file, input); err != nil {
		return err
	}
	if preserveMode {
		if err := file.Chmod(mode); err != nil {
			return err
		}
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temp, path)
}
