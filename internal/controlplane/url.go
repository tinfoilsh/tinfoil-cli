package controlplane

import (
	"fmt"
	"net/url"
)

const envControlplaneURL = "TINFOIL_CONTROLPLANE_URL"

// ValidateURL rejects URLs that would send the admin bearer
// token over plaintext HTTP. Loopback hosts are allowed for local dev so
// you can point the CLI at a controlplane running on localhost.
func ValidateURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("controlplane URL is empty (set %s or run `tinfoil login --url ...`)", envControlplaneURL)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid controlplane URL %q: %w", raw, err)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid controlplane URL %q: missing host (expected https://...)", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return fmt.Errorf("controlplane URL must not contain credentials, a query, or a fragment")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return fmt.Errorf("controlplane URL %q must use https — refusing to send admin API key over plaintext (http is allowed only for localhost)", raw)
	default:
		return fmt.Errorf("controlplane URL %q must use https://", raw)
	}
}
