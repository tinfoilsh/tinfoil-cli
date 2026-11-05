package main

import (
	"strings"

	"github.com/tinfoilsh/tinfoil-cli/internal/keybundle"
)

const (
	maxMKResources = keybundle.MaxResources
	maxBucketChars = keybundle.MaxBucketChars
)

type b64u = keybundle.Base64URL
type mkBinding = keybundle.Binding
type mkResource = keybundle.Resource
type mkPayload = keybundle.Payload
type mkContext = keybundle.Context

func decodeB64U(text string, size int) ([]byte, error) {
	return keybundle.DecodeBase64URL(text, size)
}

func validID16(id string) bool { return keybundle.ValidID16(id) }

func printableASCII(s string) bool {
	return s != "" && strings.IndexFunc(s, func(r rune) bool { return r < 0x21 || r > 0x7e }) < 0
}

func validLowerUUID(id string) bool { return looksLikeUUID(id) && id == strings.ToLower(id) }

func contractJSON(v any) ([]byte, error) { return keybundle.Marshal(v) }

func ed25519PublicKeyString(seed []byte) string { return keybundle.PublicKeyString(seed) }

func sealMK(payload *mkPayload, dek []byte, c mkContext) (string, error) {
	return keybundle.Seal(payload, dek, c)
}

func openMK(envelope string, dek []byte, c mkContext) (*mkPayload, error) {
	return keybundle.Open(envelope, dek, c)
}
