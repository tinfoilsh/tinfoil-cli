package cli

import "github.com/tinfoilsh/tinfoil-cli/internal/keybundle"

type b64u = keybundle.Base64URL
type mkResource = keybundle.Resource
type mkPayload = keybundle.Payload
type mkContext = keybundle.Context

func ed25519PublicKeyString(seed []byte) string { return keybundle.PublicKeyString(seed) }

func sealMK(payload *mkPayload, dek []byte, c mkContext) (string, error) {
	return keybundle.Seal(payload, dek, c)
}

func openMK(envelope string, dek []byte, c mkContext) (*mkPayload, error) {
	return keybundle.Open(envelope, dek, c)
}
