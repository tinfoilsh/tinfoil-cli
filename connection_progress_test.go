package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

type connectionProgressBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *connectionProgressBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}

func (b *connectionProgressBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

func TestConnectionProgressReportsLongWaitAndStopsBeforeNextStep(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var output connectionProgressBuffer
		finish := startConnectionProgress(&output, "Waiting for sandbox attestation through Monitor")
		require.Equal(t, "Waiting for sandbox attestation through Monitor...\n", output.String())
		time.Sleep(21 * time.Second)
		synctest.Wait()
		require.Contains(t, output.String(), "10s elapsed")
		require.Contains(t, output.String(), "20s elapsed")
		finish()
		finish()
		before := output.String()
		time.Sleep(time.Minute)
		synctest.Wait()
		require.Equal(t, before, output.String(), "a completed or failed step must stop reporting")
		require.NotContains(t, output.String(), "verified")
	})
}

func TestConnectionStateGuidance(t *testing.T) {
	for _, tt := range []struct{ state, hint string }{
		{"created", "still being prepared and published"},
		{"pending", "provisioning is still in progress"},
		{"deploying", "provisioning is still in progress"},
		{"started", "provisioning is still in progress"},
		{"stopping", "wait for it to stop"},
		{"stopped", "start it before connecting"},
		{"failed", "check the deployment error"},
		{"unexpected", "check its status"},
	} {
		t.Run(tt.state, func(t *testing.T) {
			require.ErrorContains(t, requireRunningConnection("Monitor", containerView{Name: "personal", Status: tt.state}), tt.hint)
		})
	}
	require.NoError(t, requireRunningConnection("Sandbox", containerView{Status: statusRunning}))
}

func TestMissingMonitorAliasFailsBeforeConnectionOrCredentialCreation(t *testing.T) {
	row := controlplaneMonitorConfig("owner")
	row.Repo = defaultSandboxRepo
	row.Volumes = map[string]string{"workspace": "11111111-1111-4111-8111-111111111111"}
	row.Config = "containers:\n  - env:\n      - SANDBOX_INSTANCE_ID: '22222222-2222-4222-8222-222222222222'\n      - MONITOR_BINDING: '{\"container_id\":\"11111111-1111-4111-8111-111111111111\",\"owner_public_key\":\"owner\"}'\n"
	row.ConfigName = "/tinfoil/containers/" + storageHash([]byte(row.Config))
	session, err := connectSandboxRow(row)
	require.Nil(t, session)
	require.ErrorContains(t, err, "requires a TCP alias")
}

func TestAttestationTransportErrorIdentifiesMonitorRouteWithoutRequestURL(t *testing.T) {
	cause := errors.New("route unavailable")
	key, expiry, err := attestConnection(func(context.Context, string, string) (net.Conn, error) {
		return nil, cause
	}, "work.invalid", defaultSandboxRepo)
	require.Nil(t, key)
	require.True(t, expiry.IsZero())
	require.ErrorIs(t, err, cause)
	require.ErrorContains(t, err, "through Monitor's SSH route")
	require.NotContains(t, err.Error(), "http://")
	require.NotContains(t, err.Error(), "nonce=")
}
