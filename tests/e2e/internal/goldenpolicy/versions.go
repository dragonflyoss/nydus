// Package goldenpolicy enforces explicit compatibility inventory requirements.
package goldenpolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const ManifestName = "manifest.json"

func Versions(root, supported string, required, configured bool) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var dirs []string
	for _, e := range entries {
		dir := filepath.Join(root, e.Name())
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			if _, err := os.Stat(filepath.Join(dir, ManifestName)); err != nil {
				return nil, fmt.Errorf("version directory %s has no manifest: %w", dir, err)
			}
			dirs = append(dirs, dir)
		}
	}
	sort.Strings(dirs)
	if len(dirs) == 0 && (required || configured) {
		return nil, fmt.Errorf("golden compatibility was required but %s has no versions", root)
	}
	for _, version := range strings.Fields(supported) {
		found := false
		for _, dir := range dirs {
			found = found || filepath.Base(dir) == version
		}
		if !found {
			return nil, fmt.Errorf("supported golden version %s is missing from %s", version, root)
		}
	}
	return dirs, nil
}
