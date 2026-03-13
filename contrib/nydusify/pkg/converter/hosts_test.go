package converter

import "testing"

func TestHosts(t *testing.T) {
	hostFunc := hosts(Opt{
		Source:            "docker.io/library/busybox:latest",
		SourceInsecure:    true,
		Target:            "registry.example.com/ns/image:converted",
		TargetInsecure:    false,
		ChunkDictRef:      "registry.example.com/ns/chunkdict:latest",
		ChunkDictInsecure: true,
		CacheRef:          "registry.example.com/ns/cache:latest",
		CacheInsecure:     false,
	})

	tests := []struct {
		name     string
		ref      string
		insecure bool
	}{
		{name: "source", ref: "docker.io/library/busybox:latest", insecure: true},
		{name: "target", ref: "registry.example.com/ns/image:converted", insecure: false},
		{name: "chunkdict", ref: "registry.example.com/ns/chunkdict:latest", insecure: true},
		{name: "cache", ref: "registry.example.com/ns/cache:latest", insecure: false},
		{name: "unknown", ref: "registry.example.com/ns/unknown:latest", insecure: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			credFunc, insecure, err := hostFunc(tc.ref)
			if err != nil {
				t.Fatalf("hosts(%q) error = %v", tc.ref, err)
			}
			if credFunc == nil {
				t.Fatalf("hosts(%q) returned nil credential func", tc.ref)
			}
			if insecure != tc.insecure {
				t.Fatalf("hosts(%q) insecure = %v, want %v", tc.ref, insecure, tc.insecure)
			}
		})
	}
}
