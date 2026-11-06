package autounlock

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/tinfoilsh/tinfoil-cli/internal/statefile"
)

const volumeIDLength = 36

type Service struct {
	directory string
	input     io.Reader
}

func NewService(directory string, input io.Reader) *Service {
	return &Service{directory: directory, input: input}
}

func validVolumeID(id string) bool {
	return len(id) == volumeIDLength && uuid.Validate(id) == nil
}

func (s *Service) MetadataPath(scope Scope, volume string) (string, error) {
	name := "profile-" + scope.Key()
	if volume != "" {
		if !validVolumeID(volume) {
			return "", fmt.Errorf("volume ID must be a UUID")
		}
		name = "volume-" + scope.Key() + "-" + strings.ToLower(volume)
	}
	return filepath.Join(s.directory, name+".json"), nil
}

func (s *Service) LoadProfile(scope Scope) (Profile, error) {
	path, err := s.MetadataPath(scope, "")
	if err != nil {
		return Profile{}, err
	}
	var p Profile
	if err := statefile.ReadJSON(path, &p); err != nil {
		return p, err
	}
	if p.Version != SchemaVersion || p.Scope != scope {
		return p, fmt.Errorf("storage profile scope/version mismatch")
	}
	return p, p.Validate()
}

func (s *Service) SaveProfile(p Profile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	path, err := s.MetadataPath(p.Scope, "")
	if err != nil {
		return err
	}
	old, err := s.LoadProfile(p.Scope)
	if err == nil {
		if old != p {
			return fmt.Errorf("storage profile already exists with different custody metadata; refusing implicit reconfiguration")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := statefile.WriteJSON(path, p, true); err != nil {
			return fmt.Errorf("saving project storage profile: %w", err)
		}
	} else {
		return err
	}
	return nil
}

func (s *Service) LoadReceipt(scope Scope, volume string) (Receipt, error) {
	path, err := s.MetadataPath(scope, volume)
	if err != nil {
		return Receipt{}, err
	}
	var r Receipt
	if err := statefile.ReadJSON(path, &r); err != nil {
		return r, err
	}
	if r.Version != SchemaVersion || r.Profile.Scope != scope || r.VolumeID != volume {
		return r, errors.New("storage receipt scope/version mismatch")
	}
	return r, nil
}
