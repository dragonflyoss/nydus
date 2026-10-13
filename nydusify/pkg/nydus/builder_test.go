package nydus

import (
	"strconv"
	"testing"
)

func TestBuildArgumentsMatchLayouts(t *testing.T) {
	for _, compressor := range []string{"", "none", "zstd", "lz4", "erofs-none", "erofs-lz4", "erofs-zstd"} {
		t.Run(compressor, func(t *testing.T) {
			for _, sourceType := range []string{"", "dir", "tar"} {
				args, err := (BuildOption{SourceDir: "source", BlobPath: "blob", Compressor: compressor, SourceType: sourceType}).args()
				if err != nil {
					t.Fatal(err)
				}
				flags := make(map[string]string)
				for index := 2; index < len(args); index += 2 {
					flags[args[index]] = args[index+1]
				}
				if flags["--chunk-size"] != strconv.Itoa(DefaultChunkSize) {
					t.Fatalf("unexpected geometry: %v", args)
				}
				if sourceType == "" {
					sourceType = "dir"
				}
				if flags["--source-type"] != sourceType {
					t.Fatalf("unexpected source type: %v", args)
				}
			}
		})
	}
}

func TestBuildRejectsUnsupportedTarOptions(t *testing.T) {
	for _, option := range []BuildOption{{SourceType: "invalid"}, {SourceType: "tar", Excludes: []string{"secret"}}} {
		if _, err := option.args(); err == nil {
			t.Fatalf("expected rejection: %+v", option)
		}
	}
}
