package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/tinfoilsh/tinfoil-cli/internal/keybundle"
)

const KeyStatePath = "/api/sandboxes/owner-key"

type KeyState struct {
	Revision    uint64          `json:"revision"`
	DEKID       *string         `json:"dek_id"`
	EncryptedMK *string         `json:"encrypted_mk"`
	Recovery    json.RawMessage `json:"recovery"`
}

type KeyStateWrite struct {
	ExpectedRevision uint64          `json:"expected_revision"`
	DEKID            string          `json:"dek_id"`
	EncryptedMK      string          `json:"encrypted_mk"`
	Recovery         json.RawMessage `json:"recovery"`
}

func (s *KeyState) Validate() error {
	if s.DEKID != nil && !keybundle.ValidID16(*s.DEKID) || (s.DEKID == nil) != (s.EncryptedMK == nil) {
		return errors.New("controlplane returned an invalid key state")
	}
	return nil
}

func (c *Client) KeyState(ctx context.Context) (*KeyState, error) {
	var state KeyState
	if _, err := c.Do(ctx, "GET", KeyStatePath, nil, nil, nil, &state); err != nil {
		return nil, fmt.Errorf("reading your key state: %w", err)
	}
	return &state, state.Validate()
}
