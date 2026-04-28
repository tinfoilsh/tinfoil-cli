package main

import "testing"

func TestPathfEscapesSegments(t *testing.T) {
	tests := []struct {
		name   string
		format string
		segs   []string
		want   string
	}{
		{
			name:   "plain segment",
			format: "/api/secrets/%s",
			segs:   []string{"DATABASE_URL"},
			want:   "/api/secrets/DATABASE_URL",
		},
		{
			name:   "hyphenated kebab name",
			format: "/api/ssh-keys/%s",
			segs:   []string{"my-deploy-key"},
			want:   "/api/ssh-keys/my-deploy-key",
		},
		{
			name:   "uuid is unchanged",
			format: "/api/containers/%s/start",
			segs:   []string{"61bd4a3e-5b48-4320-9215-0c7a7f974979"},
			want:   "/api/containers/61bd4a3e-5b48-4320-9215-0c7a7f974979/start",
		},
		{
			name:   "slash in name does not split segment",
			format: "/api/secrets/%s",
			segs:   []string{"foo/bar"},
			want:   "/api/secrets/foo%2Fbar",
		},
		{
			name:   "traversal cannot reach a sibling endpoint",
			format: "/api/ssh-keys/%s",
			segs:   []string{"../secrets/X"},
			want:   "/api/ssh-keys/..%2Fsecrets%2FX",
		},
		{
			name:   "query separator stays in segment",
			format: "/api/secrets/%s",
			segs:   []string{"foo?delete=true"},
			want:   "/api/secrets/foo%3Fdelete=true",
		},
		{
			name:   "fragment separator stays in segment",
			format: "/api/secrets/%s",
			segs:   []string{"foo#bar"},
			want:   "/api/secrets/foo%23bar",
		},
		{
			name:   "space encoded",
			format: "/api/secrets/%s",
			segs:   []string{"foo bar"},
			want:   "/api/secrets/foo%20bar",
		},
		{
			name:   "multiple segments",
			format: "/api/orgs/%s/keys/%s",
			segs:   []string{"acme/admin", "k1"},
			want:   "/api/orgs/acme%2Fadmin/keys/k1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pathf(tt.format, tt.segs...)
			if got != tt.want {
				t.Fatalf("pathf(%q, %v) = %q, want %q", tt.format, tt.segs, got, tt.want)
			}
		})
	}
}
