package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const storagePreflightVolumeID = "00000000-0000-4000-8000-000000000000"
const storageUnobserved = "awaiting publication/policy load; unlock not observed"

type storageStoreFactory func(context.Context, storageProfile) (*volumeKeyStore, error)

var volumeStorageFactory storageStoreFactory = newVolumeKeyStore

func init() {
	projectCmd.AddCommand(newProjectStorageCommand())
	volumeCmd.AddCommand(newVolumeAutoUnlockCommand(func(ctx context.Context, p storageProfile) (*volumeKeyStore, error) {
		return volumeStorageFactory(ctx, p)
	}))
	volumeCreateCmd.Flags().Bool("auto-unlock", false, "Prepare private AWS-backed automatic unlock for this new disk")
	addStorageArtifactFlags(volumeCreateCmd, false)
}

func newProjectStorageCommand() *cobra.Command {
	parent := &cobra.Command{Use: "storage", Short: "Configure customer-owned project storage", SilenceUsage: true}
	cmd := &cobra.Command{Use: "configure [id|owner/repo]", Short: "Save a local AWS keyserver profile without provisioning infrastructure", Args: cobra.MaximumNArgs(1), SilenceUsage: true}
	cmd.Flags().String("keyserver-url", "", "Customer keyserver HTTPS origin [required]")
	cmd.Flags().String("aws-region", "", "Customer AWS Secrets Manager region [required]")
	cmd.Flags().String("aws-prefix", "", "Keyserver AWS_SECRETS_PREFIX; pass an explicit empty value for no prefix [required]")
	cmd.Flags().String("aws-profile", "", "AWS shared profile (default: standard credential chain)")
	cmd.Flags().String("domain", "", "Optional exact deployment domain for policy pins")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		reader := bufio.NewReader(cmd.InOrStdin())
		identifier := ""
		if len(args) == 1 {
			identifier = args[0]
		}
		if identifier == "" {
			var err error
			identifier, err = promptStorageValue(cmd, reader, "project owner/repo", false)
			if err != nil {
				return err
			}
		}
		for _, flag := range []string{"keyserver-url", "aws-region", "aws-prefix"} {
			value, _ := cmd.Flags().GetString(flag)
			if !cmd.Flags().Changed(flag) || value == "" && flag != "aws-prefix" {
				value, err := promptStorageValue(cmd, reader, "--"+flag, flag == "aws-prefix")
				if err != nil {
					return err
				}
				if err := cmd.Flags().Set(flag, value); err != nil {
					return err
				}
			}
		}
		p := storageProfile{Version: storageSchemaVersion}
		p.KeyserverURL, _ = cmd.Flags().GetString("keyserver-url")
		p.KeyserverURL = strings.TrimRight(p.KeyserverURL, "/")
		p.AWSRegion, _ = cmd.Flags().GetString("aws-region")
		p.AWSPrefix, _ = cmd.Flags().GetString("aws-prefix")
		p.AWSProfile, _ = cmd.Flags().GetString("aws-profile")
		p.Domain, _ = cmd.Flags().GetString("domain")
		if err := p.validate(); err != nil {
			return err
		}
		client, err := authedClient()
		if err != nil {
			return err
		}
		p.Scope, err = resolveStorageScope(client, identifier)
		if err != nil {
			return err
		}
		path, err := storageMetadataPath(p.Scope, "")
		if err != nil {
			return err
		}
		old, err := loadStorageProfile(p.Scope)
		if err == nil {
			if old != p {
				return fmt.Errorf("storage profile already exists with different custody metadata; refusing implicit reconfiguration")
			}
		} else if errors.Is(err, os.ErrNotExist) {
			if err := writeStorageJSON(path, p, true); err != nil {
				return fmt.Errorf("saving project storage profile: %w", err)
			}
		} else {
			return err
		}
		if outputFormat == "json" {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"profile": p, "configuration": "PROFILE_SAVED", "policy": "not_applied"})
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Saved local AWS storage profile for %s (organization %s).\nNo keyserver or policy was deployed.\n", p.Scope.Repo, p.Scope.OrgID)
		return nil
	}
	parent.AddCommand(cmd)
	return parent
}

func promptStorageValue(cmd *cobra.Command, reader *bufio.Reader, field string, allowEmpty bool) (string, error) {
	f, ok := cmd.InOrStdin().(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return "", fmt.Errorf("%s is required; supply it explicitly in noninteractive mode", field)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "%s: ", field)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading %s failed", field)
	}
	value := strings.TrimSpace(line)
	if value == "" && !allowEmpty {
		return "", fmt.Errorf("%s is required", field)
	}
	return value, nil
}

func addStorageArtifactFlags(cmd *cobra.Command, existing bool) {
	cmd.Flags().String("project", "", "Project ID or owner/repo [required for auto-unlock]")
	cmd.Flags().String("mount", "", "Logical mount already declared in volumes [required for auto-unlock]")
	cmd.Flags().String("tag", "", "Exact new measured-config release tag to authorize [required for auto-unlock]")
	cmd.Flags().String("domain", "", "Exact deployment domain (or use storage profile domain)")
	cmd.Flags().String("config-file", "", "Existing local measured YAML input [required for auto-unlock]")
	cmd.Flags().String("config-out", "", "New prepared config output file [required for auto-unlock]")
	cmd.Flags().String("policy-file", "", "Optional local policy to extend without replacing mappings")
	cmd.Flags().String("policy-out", "", "New reviewed policy/fragment output file [required for auto-unlock]")
	if existing {
		cmd.Flags().String("existing-secret", "", "Original AWS secret name or full ARN; never a key value [required]")
	}
}

func storageOptions(cmd *cobra.Command) storageArtifactOptions {
	get := func(name string) string { value, _ := cmd.Flags().GetString(name); return value }
	return storageArtifactOptions{Project: get("project"), Mount: get("mount"), Tag: get("tag"), Domain: get("domain"), ConfigFile: get("config-file"), ConfigOut: get("config-out"), PolicyFile: get("policy-file"), PolicyOut: get("policy-out"), ExistingSecret: get("existing-secret")}
}

func newVolumeAutoUnlockCommand(factory storageStoreFactory) *cobra.Command {
	parent := &cobra.Command{Use: "auto-unlock", Short: "Prepare or inspect private volume unlock configuration", SilenceUsage: true}
	configure := &cobra.Command{Use: "configure <existing-volume>", Short: "Prepare an existing disk using only its original AWS key", Args: cobra.ExactArgs(1), SilenceUsage: true}
	addStorageArtifactFlags(configure, true)
	configure.RunE = func(cmd *cobra.Command, args []string) error {
		o := storageOptions(cmd)
		if o.ExistingSecret == "" {
			return fmt.Errorf("--existing-secret is required: existing volumes always reuse the original key, even when local configuration is missing")
		}
		if err := validateExistingSecretReference(o.ExistingSecret); err != nil {
			return err
		}
		client, err := authedClient()
		if err != nil {
			return err
		}
		p, config, policy, err := storagePreflight(client, &o, true)
		if err != nil {
			return err
		}
		v, err := lookupVolume(client, args[0])
		if err != nil {
			return err
		}
		if v.OrgID != "" && v.OrgID != p.Scope.OrgID {
			return fmt.Errorf("volume organization does not match storage profile")
		}
		store, err := factory(cmd.Context(), p)
		if err != nil {
			return err
		}
		return configureVolumeStorage(cmd, store, *v, p, o, config, policy, false)
	}
	status := &cobra.Command{Use: "status <volume>", Short: "Show local configuration evidence, not guest unlock state", Args: cobra.ExactArgs(1), SilenceUsage: true}
	status.Flags().String("project", "", "Project ID or owner/repo [required]")
	status.RunE = func(cmd *cobra.Command, args []string) error {
		project, _ := cmd.Flags().GetString("project")
		if project == "" {
			return fmt.Errorf("--project is required")
		}
		client, err := authedClient()
		if err != nil {
			return err
		}
		scope, err := resolveStorageScope(client, project)
		if err != nil {
			return err
		}
		v, err := lookupVolume(client, args[0])
		if err != nil {
			return err
		}
		state, detail, err := volumeStorageStatus(scope, v.ID)
		if err != nil {
			return err
		}
		if outputFormat == "json" {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]string{"volume_id": v.ID, "configuration": state, "detail": detail, "unlock": "not_observed"})
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Volume: %s\nAuto-unlock: %s\n%s\n", v.ID, state, detail)
		return nil
	}
	parent.AddCommand(configure, status)
	return parent
}

func storagePreflight(client *cpClient, o *storageArtifactOptions, existing bool) (storageProfile, []byte, []byte, error) {
	var p storageProfile
	if o.Project == "" {
		return p, nil, nil, fmt.Errorf("--project is required for auto-unlock")
	}
	scope, err := resolveStorageScope(client, o.Project)
	if err != nil {
		return p, nil, nil, err
	}
	p, err = loadStorageProfile(scope)
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
	config, err := readStorageInput(o.ConfigFile)
	if err != nil {
		return p, nil, nil, err
	}
	var policy []byte
	if o.PolicyFile != "" {
		policy, err = readStorageInput(o.PolicyFile)
		if err != nil {
			return p, nil, nil, err
		}
	}
	_, _, err = prepareVolumeConfig(config, p.KeyserverURL, o.Mount, volumeSecretRef(storagePreflightVolumeID), existing)
	if err != nil {
		return p, nil, nil, err
	}
	r := storageReceipt{Profile: p, VolumeID: storagePreflightVolumeID, KeySecret: volumeSecretRef(storagePreflightVolumeID), Tag: o.Tag, Domain: o.Domain}
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
			if err := probeStorageDirectory(filepath.Dir(out)); err != nil {
				return p, nil, nil, fmt.Errorf("artifact output directory is not writable: %w", err)
			}
		}
	}
	dir, err := storageDirectory()
	if err != nil {
		return p, nil, nil, err
	}
	if err := prepareStorageDirectory(dir); err != nil {
		return p, nil, nil, fmt.Errorf("preparing storage metadata directory: %w", err)
	}
	if err := probeStorageDirectory(dir); err != nil {
		return p, nil, nil, fmt.Errorf("storage metadata directory is not writable: %w", err)
	}
	return p, config, policy, nil
}

func runAutoUnlockVolumeCreate(cmd *cobra.Command, name string, factory storageStoreFactory) error {
	size, err := parseSize(volumeCreateSize)
	if err != nil {
		return fmt.Errorf("--size: %w", err)
	}
	client, err := authedClient()
	if err != nil {
		return err
	}
	o := storageOptions(cmd)
	p, config, policy, err := storagePreflight(client, &o, false)
	if err != nil {
		return err
	}
	hosts, err := listHosts(client)
	if err != nil {
		return err
	}
	host, err := pickVolumeHost(hosts, volumeCreateHost)
	if err != nil {
		return err
	}
	store, err := factory(cmd.Context(), p)
	if err != nil {
		return err
	}
	var v volumeView
	if _, err := client.do("POST", "/api/volumes", nil, map[string]any{"name": name, "host_id": host.ID, "size_bytes": size}, &v); err != nil {
		return fmt.Errorf("volume allocation outcome is unconfirmed; inspect tinfoil volume list before retrying (no automatic recreate): %w", err)
	}
	return configureVolumeStorage(cmd, store, v, p, o, config, policy, true)
}

func configureVolumeStorage(cmd *cobra.Command, store *volumeKeyStore, v volumeView, p storageProfile, o storageArtifactOptions, config, policy []byte, fresh bool) (resultErr error) {
	if !fresh {
		if err := validateExistingSecretReference(o.ExistingSecret); err != nil {
			return err
		}
	}
	r := storageReceipt{Version: storageSchemaVersion, Profile: p, VolumeID: strings.ToLower(v.ID), Mount: o.Mount, Tag: o.Tag, Domain: o.Domain, Generated: fresh, Phase: storagePhaseAllocated}
	if fresh {
		r.SecretName = volumeSecretName(p, r.VolumeID)
	}
	defer func() {
		if resultErr != nil {
			resultErr = fmt.Errorf("volume %s retained; auto-unlock phase %s: %w. Recover with tinfoil volume auto-unlock configure %s --project %s --mount %s --existing-secret %s and reviewed artifact/release flags; never recreate or format for recovery", v.ID, r.Phase, resultErr, shellQuote(v.ID), shellQuote(p.Scope.Repo), shellQuote(o.Mount), shellQuote(storageRecoveryReference(r)))
		}
	}()
	if v.OrgID != "" && v.OrgID != p.Scope.OrgID {
		return fmt.Errorf("volume organization does not match storage profile")
	}
	path, err := storageMetadataPath(p.Scope, r.VolumeID)
	if err != nil {
		return err
	}
	unlock, err := acquireStorageLock(path)
	if err != nil {
		return err
	}
	defer unlock()
	previous, err := loadStorageReceipt(p.Scope, r.VolumeID)
	hasReceipt := err == nil
	if err == nil {
		if fresh {
			return fmt.Errorf("allocated volume ID already has a custody receipt; refusing new key")
		}
		if previous.Profile != p || previous.Mount != o.Mount {
			return fmt.Errorf("existing custody profile/mount differs; refusing implicit reassignment")
		}
		r = previous
		r.Tag, r.Domain = o.Tag, o.Domain
		if !r.Generated && (r.SecretARN == "" || r.SecretVersion == "") {
			r.SecretName = ""
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	ref := r.KeySecret
	if ref == "" {
		ref = volumeSecretRef(r.VolumeID)
	}
	preparedConfig, ref, err := prepareVolumeConfig(config, p.KeyserverURL, o.Mount, ref, !fresh)
	if err != nil {
		return err
	}
	if r.KeySecret != "" && r.KeySecret != ref {
		return fmt.Errorf("refusing to replace the original measured key-secret reference")
	}
	r.KeySecret = ref
	if !fresh {
		r.Phase = storagePhaseVerifying
	}
	if fresh {
		if err := writeStorageJSON(path, r, fresh); err != nil {
			return err
		}
	}
	var stored storedVolumeKey
	if fresh {
		stored, err = store.create(cmd.Context(), r, func() error {
			r.Phase = storagePhaseAttempted
			return writeStorageJSON(path, r, false)
		})
	} else {
		stored, err = store.read(cmd.Context(), o.ExistingSecret, &r)
	}
	if err != nil {
		if !fresh && hasReceipt {
			if saveErr := writeStorageJSON(path, r, false); saveErr != nil {
				return errors.Join(err, fmt.Errorf("recording secret verification failure: %w", saveErr))
			}
		}
		return err
	}
	r.SecretName, r.SecretARN, r.SecretVersion = stored.Name, stored.ARN, stored.Version
	r.Phase = storagePhaseStored
	if fresh {
		if err := writeStorageJSON(path, r, false); err != nil {
			return err
		}
	}
	secretPath, err := storagePolicyPath(p, stored.Name)
	if err != nil {
		return err
	}
	preparedPolicy, err := prepareVolumePolicy(policy, r, secretPath)
	if err != nil {
		return err
	}
	if !fresh {
		if err := preflightStorageArtifacts([]storageArtifact{{path: o.ConfigOut, data: preparedConfig}, {path: o.PolicyOut, data: preparedPolicy}}); err != nil {
			return err
		}
		if err := writeStorageJSON(path, r, false); err != nil {
			return err
		}
	}
	if err := writeStorageArtifact(o.ConfigOut, preparedConfig); err != nil {
		return err
	}
	if err := writeStorageArtifact(o.PolicyOut, preparedPolicy); err != nil {
		return err
	}
	r.ConfigPath, err = filepath.Abs(o.ConfigOut)
	if err != nil {
		return err
	}
	r.PolicyPath, err = filepath.Abs(o.PolicyOut)
	if err != nil {
		return err
	}
	r.ConfigHash, r.PolicyHash = storageHash(preparedConfig), storageHash(preparedPolicy)
	r.Phase = storagePhasePrepared
	if err := writeStorageJSON(path, r, false); err != nil {
		return err
	}
	return printStoragePrepared(cmd.OutOrStdout(), r)
}

func storageRecoveryReference(r storageReceipt) string {
	if r.Generated {
		return volumeSecretName(r.Profile, r.VolumeID)
	}
	if r.SecretARN != "" && r.SecretVersion != "" {
		return r.SecretARN
	}
	return "<original-secret-name-or-arn>"
}

func printStoragePrepared(out io.Writer, r storageReceipt) error {
	if outputFormat == "json" {
		return json.NewEncoder(out).Encode(map[string]any{"receipt": r, "configuration": "CONFIGURED_LOCAL", "detail": storageUnobserved, "unlock": "not_observed"})
	}
	fmt.Fprintf(out, "Volume: %s\nAuto-unlock: CONFIGURED_LOCAL\n%s\nConfig: %s\nPolicy: %s\n", r.VolumeID, storageUnobserved, r.ConfigPath, r.PolicyPath)
	fmt.Fprintf(out, "Review config, then propose: tinfoil repo config pr %s --file %s\nAfter review/merge: tinfoil repo build run %s --version %s\n", shellQuote(r.Profile.Scope.Repo), shellQuote(r.ConfigPath), shellQuote(r.Profile.Scope.Repo), shellQuote(r.Tag))
	fmt.Fprintln(out, "Wait for release workflows and publication. Independently review/merge/install the policy and restart your keyserver; no remote approval was performed.")
	fmt.Fprintln(out, "Deploy the exact repo/tag/domain with this original disk and --secret=\"\". The guest must finish its boot mount stage; no manual per-boot decrypt is needed.")
	return nil
}

func volumeStorageStatus(scope storageScope, id string) (string, string, error) {
	p, err := loadStorageProfile(scope)
	if errors.Is(err, os.ErrNotExist) {
		return "UNKNOWN", "No local storage profile for this scope; this is not evidence of a locked disk or key loss. Unlock not observed.", nil
	}
	if err != nil {
		return "", "", err
	}
	r, err := loadStorageReceipt(scope, strings.ToLower(id))
	if errors.Is(err, os.ErrNotExist) {
		return "UNKNOWN", "No local volume receipt; ask the storage owner for configuration metadata. Unlock not observed.", nil
	}
	if err != nil {
		return "", "", err
	}
	if r.Phase != storagePhasePrepared {
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
	return "CONFIGURED_LOCAL", storageUnobserved, nil
}
