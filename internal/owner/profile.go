// Package owner manages resource credentials and attested owner sessions.
package owner

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/tinfoilsh/tinfoil-cli/internal/statefile"
)

const (
	ProfileFile         = "profile.json"
	profileLockAttempts = 50
	profileLockRetry    = 20 * time.Millisecond
)

// Persist the domain, boot key and minimum generation.
type Profile struct {
	Domain      string `json:"domain"`
	Address     string `json:"address,omitempty"`
	ContainerID string `json:"container_id,omitempty"`
	Owner       string `json:"owner_public_key,omitempty"`
	HostKey     string `json:"host_key,omitempty"`
	Generation  uint64 `json:"generation"`
	Custody     string `json:"custody,omitempty"`
}

// Serialize updates to preserve boot-key pins and the maximum generation.
func UpdateProfile(dir string, update func(*Profile) error) (Profile, error) {
	path := filepath.Join(dir, ProfileFile)
	unlock, err := statefile.Lock(path)
	for attempt := 1; err != nil && attempt < profileLockAttempts; attempt++ {
		time.Sleep(profileLockRetry)
		unlock, err = statefile.Lock(path)
	}
	if err != nil {
		return Profile{}, err
	}
	defer unlock()
	var profile Profile
	if err := statefile.ReadJSON(path, &profile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return profile, err
	}
	if err := update(&profile); err != nil {
		return profile, err
	}
	return profile, statefile.WriteJSON(path, profile, false)
}
