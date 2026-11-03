package env

import (
	"os"
	"strconv"
	"testing"
	"time"
)

// Int reads the integer knob key, or def when it is unset.
func Int(t testing.TB, key string, def int) int {
	t.Helper()
	return lookup(t, key, def, strconv.Atoi)
}

// Bool reads the boolean knob key, or def when it is unset.
func Bool(t testing.TB, key string, def bool) bool {
	t.Helper()
	return lookup(t, key, def, strconv.ParseBool)
}

// Duration reads the duration knob key, or def when it is unset.
func Duration(t testing.TB, key string, def time.Duration) time.Duration {
	t.Helper()
	return lookup(t, key, def, time.ParseDuration)
}

// lookup reads knob key with parse, or def when it is unset. A value parse
// rejects fails t: a mistyped knob must not silently run the default.
func lookup[T any](t testing.TB, key string, def T, parse func(string) (T, error)) T {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		return def
	}

	value, err := parse(v)
	if err != nil {
		t.Fatalf("%s=%q: %v", key, v, err)
	}

	return value
}
