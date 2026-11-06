package controlplane

import (
	"strings"
	"testing"
)

func TestValidateControlplaneURL(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantError bool
		errSubstr string
	}{
		{name: "https default", input: "https://api.tinfoil.sh"},
		{name: "https with port and path", input: "https://api.tinfoil.sh:8443/cp"},
		{name: "https subdomain", input: "https://staging.api.tinfoil.sh"},

		{name: "http localhost", input: "http://localhost:8080"},
		{name: "http 127.0.0.1", input: "http://127.0.0.1:8080"},
		{name: "http ::1", input: "http://[::1]:8080"},

		{name: "empty", input: "", wantError: true, errSubstr: "empty"},
		{name: "no scheme", input: "api.tinfoil.sh", wantError: true, errSubstr: "missing host"},
		{name: "http public", input: "http://api.tinfoil.sh", wantError: true, errSubstr: "must use https"},
		{name: "http with userinfo", input: "http://user:pass@attacker.example.com", wantError: true, errSubstr: "must not contain"},
		{name: "ftp", input: "ftp://api.tinfoil.sh", wantError: true, errSubstr: "must use https"},
		{name: "ws", input: "ws://api.tinfoil.sh", wantError: true, errSubstr: "must use https"},
		{name: "https no host", input: "https://", wantError: true, errSubstr: "missing host"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateURL(tt.input)
			if tt.wantError {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tt.input)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.input, err)
			}
		})
	}
}
