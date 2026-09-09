package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRequestHeaders(t *testing.T) {
	headers, err := parseRequestHeaders([]string{
		"Authorization: Bearer token",
		"Content-Type: application/json",
		"X-Trace: value:with:colons",
	})

	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"Authorization": "Bearer token",
		"Content-Type":  "application/json",
		"X-Trace":       "value:with:colons",
	}, headers)
}

func TestParseRequestHeadersReturnsNilForEmptyInput(t *testing.T) {
	headers, err := parseRequestHeaders(nil)

	require.NoError(t, err)
	assert.Nil(t, headers)
}

func TestParseRequestHeadersRejectsMalformedHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
	}{
		{
			name:    "missing colon",
			headers: []string{"Authorization Bearer token"},
		},
		{
			name:    "empty name",
			headers: []string{": Bearer token"},
		},
		{
			name:    "newline in value",
			headers: []string{"Authorization: Bearer token\nX-Other: value"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseRequestHeaders(test.headers)
			assert.Error(t, err)
		})
	}
}

func TestHTTPRequiresHostAndRepo(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		repo    string
		wantErr bool
	}{
		{name: "both missing", wantErr: true},
		{name: "repo missing", host: "inference.tinfoil.sh", wantErr: true},
		{name: "host missing", repo: "tinfoilsh/confidential-model-router", wantErr: true},
		{name: "both set", host: "inference.tinfoil.sh", repo: "tinfoilsh/confidential-model-router"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			enclaveHost, repo = test.host, test.repo
			t.Cleanup(func() { enclaveHost, repo = "", "" })

			err := httpCmd.PersistentPreRunE(httpGetCmd, nil)
			if test.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHasRequestHeaderIgnoresCase(t *testing.T) {
	assert.True(t, hasRequestHeader(map[string]string{
		"content-type": "application/json",
	}, "Content-Type"))
}
