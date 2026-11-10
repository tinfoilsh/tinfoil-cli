package connection

import (
	"context"
	"fmt"

	"github.com/tinfoilsh/tinfoil-go"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

type Verification struct {
	Reference      string
	Config         *Config
	RegistryIDs    []string
	PublicRegistry bool
	RTMR3          string
}

func (v Verification) Options() (*tinfoil.EnclaveOptions, error) {
	var policy []verify.Option
	if v.Config != nil {
		if v.PublicRegistry {
			return nil, fmt.Errorf("--public-registry and --config cannot be used together")
		}
		if v.Reference != "" {
			return nil, fmt.Errorf("--config and --repo cannot be used together")
		}
		policy = append(policy, verify.WithEmbeddedReferences(verify.EmbeddedReferences{Config: &verify.EmbeddedConfig{Bytes: v.Config.Bytes()}}))
	} else if v.Reference == "" {
		return nil, fmt.Errorf("v3 verification requires an expected workload; pass --repo owner/name[@tag][@sha256:digest] or --config FILE")
	} else if !v.PublicRegistry && len(v.RegistryIDs) != 0 {
		policy = append(policy, verify.WithAdditionalConfigRegistryIDs(v.RegistryIDs...))
	}
	if v.RTMR3 != "" {
		pins, err := measurement.ParseExpectedTDX("", "", "", "", v.RTMR3)
		if err != nil {
			return nil, err
		}
		policy = append(policy, verify.WithPinnedRegisters(pins))
	}
	verifier, err := verify.NewVerifier(policy...)
	if err != nil {
		return nil, err
	}
	return &tinfoil.EnclaveOptions{Verifier: verifier}, nil
}

func NewClient(ctx context.Context, host string, verification Verification) (*tinfoil.EnclaveHTTPClient, error) {
	if host == "" {
		return nil, fmt.Errorf("--enclave is required")
	}
	opts, err := verification.Options()
	if err != nil {
		return nil, err
	}
	return tinfoil.NewEnclaveHTTPClient(ctx, host, verification.Reference, opts)
}
