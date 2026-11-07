package owner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStoppedWorkloadsPointAtTheirStartCommand(t *testing.T) {
	stopped := &Workload{Container: containerView{Name: "work", Status: "stopped"}}
	_, err := SandboxBinding(Scope{}, stopped)
	require.EqualError(t, err, "Bunker work is Stopped; run `tinfoil bunker start work`")
	_, err = testService().ConnectMonitor(t.Context(), Scope{}, nil, stopped, false, nil)
	require.EqualError(t, err, "Perimeter work is Stopped; run `tinfoil perimeter start work`")
}
