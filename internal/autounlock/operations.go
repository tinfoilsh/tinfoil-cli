package autounlock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tinfoilsh/tinfoil-cli/internal/statefile"
)

const storagePreflightVolumeID = "00000000-0000-4000-8000-000000000000"
const Unobserved = "awaiting publication/policy load; unlock not observed"

type ConfigureRequest struct {
	VolumeID string
	OrgID    string
	Profile  Profile
	Options  ArtifactOptions
	Config   []byte
	Policy   []byte
	Fresh    bool
}

type RecoveryError struct {
	VolumeID string
	Receipt  Receipt
	Err      error
}

func (e *RecoveryError) Error() string {
	return fmt.Sprintf("volume %s retained; auto-unlock phase %s: %v", e.VolumeID, e.Receipt.Phase, e.Err)
}

func (e *RecoveryError) Unwrap() error { return e.Err }

func (r Receipt) RecoveryReference() string {
	if r.Generated {
		return volumeSecretName(r.Profile, r.VolumeID)
	}
	if r.SecretARN != "" && r.SecretVersion != "" {
		return r.SecretARN
	}
	return "<original-secret-name-or-arn>"
}

func (s *Service) Preflight(scope Scope, o *ArtifactOptions, existing bool) (Profile, []byte, []byte, error) {
	p, err := s.LoadProfile(scope)
	if errors.Is(err, os.ErrNotExist) {
		return p, nil, nil, fmt.Errorf("no local storage profile for this controlplane/organization/project; run tinfoil project storage configure %s", scope.Repo)
	}
	if err != nil {
		return p, nil, nil, err
	}
	if o.Domain == "" {
		o.Domain = p.Domain
	}
	if err := o.validate(p); err != nil {
		return p, nil, nil, err
	}
	config, err := readStorageInput(o.ConfigFile, s.input)
	if err != nil {
		return p, nil, nil, err
	}
	var policy []byte
	if o.PolicyFile != "" {
		policy, err = readStorageInput(o.PolicyFile, s.input)
		if err != nil {
			return p, nil, nil, err
		}
	}
	_, _, err = prepareVolumeConfig(config, p.KeyserverURL, o.Mount, volumeSecretRef(storagePreflightVolumeID), existing)
	if err != nil {
		return p, nil, nil, err
	}
	r := Receipt{Profile: p, VolumeID: storagePreflightVolumeID, KeySecret: volumeSecretRef(storagePreflightVolumeID), Tag: o.Tag, Domain: o.Domain}
	if _, err := prepareVolumePolicy(policy, r, "volumes/"+storagePreflightVolumeID+"/key"); err != nil {
		return p, nil, nil, err
	}
	for _, out := range []string{o.ConfigOut, o.PolicyOut} {
		info, err := os.Stat(filepath.Dir(out))
		if err != nil || !info.IsDir() {
			return p, nil, nil, fmt.Errorf("artifact output parent directory must exist")
		}
		if !existing {
			if _, err := os.Lstat(out); err == nil {
				return p, nil, nil, fmt.Errorf("new-volume output path already exists; choose a new path before allocating")
			} else if !errors.Is(err, os.ErrNotExist) {
				return p, nil, nil, err
			}
			if err := statefile.ProbeDirectory(filepath.Dir(out)); err != nil {
				return p, nil, nil, fmt.Errorf("artifact output directory is not writable: %w", err)
			}
		}
	}
	if err := statefile.PrepareDirectory(s.directory); err != nil {
		return p, nil, nil, fmt.Errorf("preparing storage metadata directory: %w", err)
	}
	if err := statefile.ProbeDirectory(s.directory); err != nil {
		return p, nil, nil, fmt.Errorf("storage metadata directory is not writable: %w", err)
	}
	return p, config, policy, nil
}

func (s *Service) Configure(ctx context.Context, store *KeyStore, request ConfigureRequest) (receipt Receipt, resultErr error) {
	p, o, config, policy, fresh := request.Profile, request.Options, request.Config, request.Policy, request.Fresh
	if !fresh {
		if err := ValidateExistingSecretReference(o.ExistingSecret); err != nil {
			return receipt, err
		}
	}
	r := Receipt{Version: SchemaVersion, Profile: p, VolumeID: strings.ToLower(request.VolumeID), Mount: o.Mount, Tag: o.Tag, Domain: o.Domain, Generated: fresh, Phase: PhaseAllocated}
	if fresh {
		r.SecretName = volumeSecretName(p, r.VolumeID)
	}
	defer func() {
		if resultErr != nil {
			resultErr = &RecoveryError{VolumeID: request.VolumeID, Receipt: r, Err: resultErr}
		}
	}()
	if request.OrgID != "" && request.OrgID != p.Scope.OrgID {
		return receipt, fmt.Errorf("volume organization does not match storage profile")
	}
	path, err := s.MetadataPath(p.Scope, r.VolumeID)
	if err != nil {
		return receipt, err
	}
	unlock, err := statefile.Lock(path)
	if err != nil {
		return receipt, err
	}
	defer unlock()
	previous, err := s.LoadReceipt(p.Scope, r.VolumeID)
	hasReceipt := err == nil
	if err == nil {
		if fresh {
			return receipt, fmt.Errorf("allocated volume ID already has a custody receipt; refusing new key")
		}
		if previous.Profile != p || previous.Mount != o.Mount {
			return receipt, fmt.Errorf("existing custody profile/mount differs; refusing implicit reassignment")
		}
		r = previous
		r.Tag, r.Domain = o.Tag, o.Domain
		if !r.Generated && (r.SecretARN == "" || r.SecretVersion == "") {
			r.SecretName = ""
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return receipt, err
	}
	ref := r.KeySecret
	if ref == "" {
		ref = volumeSecretRef(r.VolumeID)
	}
	preparedConfig, ref, err := prepareVolumeConfig(config, p.KeyserverURL, o.Mount, ref, !fresh)
	if err != nil {
		return receipt, err
	}
	if r.KeySecret != "" && r.KeySecret != ref {
		return receipt, fmt.Errorf("refusing to replace the original measured key-secret reference")
	}
	r.KeySecret = ref
	if !fresh {
		r.Phase = PhaseVerifying
	}
	if fresh {
		if err := statefile.WriteJSON(path, r, fresh); err != nil {
			return receipt, err
		}
	}
	var stored storedVolumeKey
	if fresh {
		stored, err = store.create(ctx, r, func() error {
			r.Phase = PhaseAttempted
			return statefile.WriteJSON(path, r, false)
		})
	} else {
		stored, err = store.read(ctx, o.ExistingSecret, &r)
	}
	if err != nil {
		if !fresh && hasReceipt {
			if saveErr := statefile.WriteJSON(path, r, false); saveErr != nil {
				return receipt, errors.Join(err, fmt.Errorf("recording secret verification failure: %w", saveErr))
			}
		}
		return receipt, err
	}
	r.SecretName, r.SecretARN, r.SecretVersion = stored.Name, stored.ARN, stored.Version
	r.Phase = PhaseStored
	if fresh {
		if err := statefile.WriteJSON(path, r, false); err != nil {
			return receipt, err
		}
	}
	secretPath, err := storagePolicyPath(p, stored.Name)
	if err != nil {
		return receipt, err
	}
	preparedPolicy, err := prepareVolumePolicy(policy, r, secretPath)
	if err != nil {
		return receipt, err
	}
	if !fresh {
		if err := preflightStorageArtifacts([]storageArtifact{{path: o.ConfigOut, data: preparedConfig}, {path: o.PolicyOut, data: preparedPolicy}}); err != nil {
			return receipt, err
		}
		if err := statefile.WriteJSON(path, r, false); err != nil {
			return receipt, err
		}
	}
	if err := writeStorageArtifact(o.ConfigOut, preparedConfig); err != nil {
		return receipt, err
	}
	if err := writeStorageArtifact(o.PolicyOut, preparedPolicy); err != nil {
		return receipt, err
	}
	r.ConfigPath, err = filepath.Abs(o.ConfigOut)
	if err != nil {
		return receipt, err
	}
	r.PolicyPath, err = filepath.Abs(o.PolicyOut)
	if err != nil {
		return receipt, err
	}
	r.ConfigHash, r.PolicyHash = storageHash(preparedConfig), storageHash(preparedPolicy)
	r.Phase = PhasePrepared
	if err := statefile.WriteJSON(path, r, false); err != nil {
		return receipt, err
	}
	return r, nil
}

func (s *Service) Status(scope Scope, id string) (string, string, error) {
	p, err := s.LoadProfile(scope)
	if errors.Is(err, os.ErrNotExist) {
		return "UNKNOWN", "No local storage profile for this scope; this is not evidence of a locked disk or key loss. Unlock not observed.", nil
	}
	if err != nil {
		return "", "", err
	}
	r, err := s.LoadReceipt(scope, strings.ToLower(id))
	if errors.Is(err, os.ErrNotExist) {
		return "UNKNOWN", "No local volume receipt; ask the storage owner for configuration metadata. Unlock not observed.", nil
	}
	if err != nil {
		return "", "", err
	}
	if r.Phase != PhasePrepared {
		return "INCOMPLETE", "Recovery phase: " + r.Phase + "; unlock not observed", nil
	}
	if r.Profile != p || r.KeySecret == "" || r.SecretARN == "" || r.SecretVersion == "" || r.ConfigHash == "" || r.PolicyHash == "" {
		return "STALE", "Local custody metadata disagrees; unlock not observed", nil
	}
	for path, hash := range map[string]string{r.ConfigPath: r.ConfigHash, r.PolicyPath: r.PolicyHash} {
		data, err := os.ReadFile(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return "", "", fmt.Errorf("reading local configuration evidence: %w", err)
			}
			return "STALE", "Prepared artifact is missing; unlock not observed", nil
		}
		if storageHash(data) != hash {
			return "STALE", "Prepared artifact changed (measurements/policy require review); unlock not observed", nil
		}
	}
	return "CONFIGURED_LOCAL", Unobserved, nil
}
