package connection

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"golang.org/x/crypto/ssh"
)

// attestedHostKeyID is the attested-keys declaration a workload serves as its sshd HostKey.
const attestedHostKeyID = "host-ssh"

// AttestedHostKey verifies host against source and returns the endorsed
// host-ssh key, so a failed verification never falls back to unverified acceptance.
func AttestedHostKey(ctx context.Context, host string, verification Verification) (ssh.PublicKey, error) {
	secure, err := NewClient(ctx, host, verification)
	if err != nil {
		return nil, err
	}
	verified, err := secure.EnsureVerified(ctx)
	if err != nil {
		return nil, fmt.Errorf("verifying %s: %w", host, err)
	}
	return EndorsedHostKey(host, verified)
}

type Evidence interface {
	CryptoMaterialData(string, string) (string, bool)
	FreshnessExpiresAt() time.Time
}

func EndorsedHostKey(host string, verified Evidence) (ssh.PublicKey, error) {
	public, err := endorsedKey(host, verified, attestedHostKeyID)
	if err != nil {
		return nil, err
	}
	return ssh.NewPublicKey(public)
}

func endorsedKey(host string, verified Evidence, id string) (any, error) {
	data, ok := verified.CryptoMaterialData(id, document.KeySPKIV1Format)
	if !ok {
		return nil, fmt.Errorf("%s endorses no attested %q key", host, id)
	}
	der, err := hex.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("attested %q key is not hex: %w", id, err)
	}
	public, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("attested %q key is not SPKI: %w", id, err)
	}
	return public, nil
}
