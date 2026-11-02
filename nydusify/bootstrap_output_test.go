package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveBootstrapRejectsUnusableDestination(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	if err := os.WriteFile(source, []byte("bootstrap"), 0600); err != nil {
		t.Fatal(err)
	}
	loop := filepath.Join(dir, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{loop, filepath.Join(dir, "missing", "image.boot")} {
		if err := saveBootstrap(target, source); err == nil {
			t.Fatalf("accepted unusable destination %s", target)
		}
	}
	data, err := os.ReadFile(source)
	if err != nil || string(data) != "bootstrap" {
		t.Fatalf("source changed: %q, %v", data, err)
	}
	entries, err := filepath.Glob(filepath.Join(dir, ".image.boot-*"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary files: %v, %v", entries, err)
	}
}

func TestSaveBootstrapPreservesPermissions(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode os.FileMode
	}{
		{"0644", 0644}, {"0640", 0640}, {"0444", 0444},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			source, target := filepath.Join(dir, "source"), filepath.Join(dir, "target")
			if err := os.WriteFile(source, []byte("new"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte("old"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(target, tc.mode); err != nil {
				t.Fatal(err)
			}
			for _, input := range []string{source, target} {
				if err := saveBootstrap(target, input); err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(target)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != tc.mode {
					t.Fatalf("mode=%o, want %o", info.Mode().Perm(), tc.mode)
				}
				data, err := os.ReadFile(target)
				if err != nil || string(data) != "new" {
					t.Fatalf("data=%q error=%v", data, err)
				}
			}
		})
	}
}

func TestSaveBootstrapStreamsLargeFileAndKeepsFailedDestination(t *testing.T) {
	dir := t.TempDir()
	source, target := filepath.Join(dir, "source"), filepath.Join(dir, "target")
	file, err := os.Create(source)
	if err != nil {
		t.Fatal(err)
	}
	const size = 16 << 20
	if err := file.Truncate(size); err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("tail"), size-4); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := saveBootstrap(target, source); err != nil {
		t.Fatal(err)
	}
	output, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	info, err := output.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != size || info.Mode().Perm() != 0600 {
		t.Fatalf("size=%d mode=%o", info.Size(), info.Mode().Perm())
	}
	var tail [4]byte
	if _, err := output.ReadAt(tail[:], size-4); err != nil {
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	if string(tail[:]) != "tail" {
		t.Fatalf("tail=%q", tail)
	}
	for _, bad := range []string{filepath.Join(dir, "missing"), dir} {
		if err := saveBootstrap(target, bad); err == nil {
			t.Fatal("expected source read failure")
		}
		info, err := os.Stat(target)
		if err != nil || info.Size() != size {
			t.Fatalf("destination changed: %v", err)
		}
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".image.boot-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary files left: %v, error=%v", matches, err)
	}
}

func TestSaveBootstrapReplacesInputWithoutChangingRetainedLink(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "image.boot")
	retained := filepath.Join(dir, "retained.boot")
	if err := os.WriteFile(input, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(input, retained); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "final.boot")
	if err := os.WriteFile(source, []byte("compacted"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := saveBootstrap(input, source); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{input: "compacted", retained: "original"} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != want {
			t.Fatalf("read %s: data=%q err=%v, want %q", path, data, err, want)
		}
	}
	// A rename failure must leave its destination and no temporary files.
	dest := filepath.Join(dir, "directory")
	if err := os.Mkdir(dest, 0700); err != nil {
		t.Fatal(err)
	}
	if err := saveBootstrap(dest, source); err == nil {
		t.Fatal("expected rename failure")
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".image.boot-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary files left: %v, err=%v", matches, err)
	}
}
