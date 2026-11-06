package autounlock

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStorageProfileAllowsHTTPSPortBoundaries(t *testing.T) {
	for _, endpoint := range []string{"https://keys.example.com", "https://keys.example.com/", "https://keys.example.com:1", "https://keys.example.com:443", "https://keys.example.com:65535", "https://[2001:db8::1]", "https://[2001:db8::1]:8443"} {
		t.Run(endpoint, func(t *testing.T) {
			p := testStorageProfile()
			p.KeyserverURL = endpoint
			require.NoError(t, p.Validate())
		})
	}
}
