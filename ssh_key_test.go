package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSSHKeyCommandsSelectTheSandboxListWithFlag(t *testing.T) {
	for _, sandbox := range []bool{false, true} {
		var requests []string
		managedTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
			requests = append(requests, r.Method+" "+r.URL.RequestURI())
			key := sshKeyView{Name: "laptop", KeyType: "ssh-ed25519", Sandbox: sandbox}
			if r.Method == http.MethodGet {
				json.NewEncoder(w).Encode([]sshKeyView{key})
				return
			}
			json.NewEncoder(w).Encode(key)
		})
		var flags []string
		query := ""
		if sandbox {
			flags, query = []string{"--sandbox"}, "?sandbox=true"
		}
		for _, args := range [][]string{{"list"}, {"create", "laptop", "--public-key", "ssh-ed25519 AAAA"}, {"delete", "laptop"}} {
			_, err := captureTestStdout(func() error {
				return executeLifecycleCLI(t, append(append([]string{"ssh-key"}, args...), flags...)...)
			})
			require.NoError(t, err)
		}
		require.Equal(t, []string{"GET /api/ssh-keys" + query, "POST /api/ssh-keys" + query, "DELETE /api/ssh-keys/laptop" + query}, requests)
	}
}
