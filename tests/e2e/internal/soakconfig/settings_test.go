package soakconfig

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSettings(t *testing.T) {
	t.Parallel()
	s, err := Parse(func(string) string { return "" })
	require.NoError(t, err)
	require.Equal(t, 30*time.Second, s.Duration)
	require.Equal(t, 20, s.Cycles)
	for key, values := range map[string][]string{
		"NYDUS_E2E_SOAK_DURATION": {"garbage", "-1s", "9s", "25h"},
		"NYDUS_E2E_SOAK_CYCLES":   {"0", "-1", "bad", "100001"},
		"NYDUS_E2E_SOAK_RSS_MIB":  {"0", "-1", "NaN", "1048577"},
	} {
		for _, value := range values {
			t.Run(key+"/"+value, func(t *testing.T) {
				t.Parallel()
				_, err := Parse(func(k string) string {
					if k == key {
						return value
					}
					return ""
				})
				require.Error(t, err)
			})
		}
	}
	s, err = Parse(func(key string) string {
		return map[string]string{"NYDUS_E2E_SOAK_DURATION": "1h", "NYDUS_E2E_SOAK_CYCLES": "120", "NYDUS_E2E_SOAK_RSS_MIB": "64"}[key]
	})
	require.NoError(t, err)
	require.Equal(t, Settings{time.Hour, 120, 64 << 20}, s)
}
