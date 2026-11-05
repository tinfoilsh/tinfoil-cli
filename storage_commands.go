package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tinfoil-cli/internal/autounlock"
	"golang.org/x/term"
)

const storageUnobserved = autounlock.Unobserved

type storageStoreFactory func(context.Context, storageProfile) (*volumeKeyStore, error)

func newProjectStorageCommand(newClient authenticatedClientFactory, outputOpts *outputOptions) *cobra.Command {
	parent := &cobra.Command{Use: "storage", Short: "Configure customer-owned project storage"}
	cmd := &cobra.Command{Use: "configure [id|owner/repo]", Short: "Save a local AWS keyserver profile without provisioning infrastructure", Args: cobra.MaximumNArgs(1)}
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
		if err := p.Validate(); err != nil {
			return err
		}
		client, err := newClient(commandStreams(cmd))
		if err != nil {
			return err
		}
		p.Scope, err = resolveStorageScope(client, identifier)
		if err != nil {
			return err
		}
		service, err := newStorageService()
		if err != nil {
			return err
		}
		if err := service.SaveProfile(p); err != nil {
			return err
		}
		if outputOpts.outputFormat == "json" {
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

func newVolumeAutoUnlockCommand(newClient authenticatedClientFactory, outputOpts *outputOptions, factory storageStoreFactory) *cobra.Command {
	parent := &cobra.Command{Use: "auto-unlock", Short: "Prepare or inspect private volume unlock configuration"}
	configure := &cobra.Command{Use: "configure <existing-volume>", Short: "Prepare an existing disk using only its original AWS key", Args: cobra.ExactArgs(1)}
	addStorageArtifactFlags(configure, true)
	configure.RunE = func(cmd *cobra.Command, args []string) error {
		o := storageOptions(cmd)
		if o.ExistingSecret == "" {
			return fmt.Errorf("--existing-secret is required: existing volumes always reuse the original key, even when local configuration is missing")
		}
		if err := autounlock.ValidateExistingSecretReference(o.ExistingSecret); err != nil {
			return err
		}
		client, err := newClient(commandStreams(cmd))
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
		return configureVolumeStorage(outputOpts, cmd, store, *v, p, o, config, policy, false)
	}
	status := &cobra.Command{Use: "status <volume>", Short: "Show local configuration evidence, not guest unlock state", Args: cobra.ExactArgs(1)}
	status.Flags().String("project", "", "Project ID or owner/repo [required]")
	status.RunE = func(cmd *cobra.Command, args []string) error {
		project, _ := cmd.Flags().GetString("project")
		if project == "" {
			return fmt.Errorf("--project is required")
		}
		client, err := newClient(commandStreams(cmd))
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
		if outputOpts.outputFormat == "json" {
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
	service, err := newStorageService()
	if err != nil {
		return p, nil, nil, err
	}
	return service.Preflight(scope, o, existing)
}

func runAutoUnlockVolumeCreate(newClient authenticatedClientFactory, outputOpts *outputOptions, volumeCreateOpts *volumeCreateOptions, cmd *cobra.Command, name string, factory storageStoreFactory) error {
	size, err := parseSize(volumeCreateOpts.volumeCreateSize)
	if err != nil {
		return fmt.Errorf("--size: %w", err)
	}
	client, err := newClient(commandStreams(cmd))
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
	host, err := pickVolumeHost(hosts, volumeCreateOpts.volumeCreateHost)
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
	return configureVolumeStorage(outputOpts, cmd, store, v, p, o, config, policy, true)
}

func configureVolumeStorage(outputOpts *outputOptions, cmd *cobra.Command, store *volumeKeyStore, v volumeView, p storageProfile, o storageArtifactOptions, config, policy []byte, fresh bool) error {
	if !fresh {
		if err := autounlock.ValidateExistingSecretReference(o.ExistingSecret); err != nil {
			return err
		}
	}
	service, err := newStorageService()
	var r storageReceipt
	if err != nil {
		r = storageReceipt{Profile: p, VolumeID: strings.ToLower(v.ID), Mount: o.Mount, Generated: fresh, Phase: autounlock.PhaseAllocated}
		err = &autounlock.RecoveryError{VolumeID: v.ID, Receipt: r, Err: err}
	} else {
		r, err = service.Configure(cmd.Context(), store, autounlock.ConfigureRequest{
			VolumeID: v.ID, OrgID: v.OrgID, Profile: p, Options: o, Config: config, Policy: policy, Fresh: fresh,
		})
		if err == nil {
			if outputErr := printStoragePrepared(outputOpts, cmd.OutOrStdout(), r); outputErr != nil {
				err = &autounlock.RecoveryError{VolumeID: v.ID, Receipt: r, Err: outputErr}
			}
		}
	}
	var recovery *autounlock.RecoveryError
	if errors.As(err, &recovery) {
		return fmt.Errorf("%w. Recover with tinfoil volume auto-unlock configure %s --project %s --mount %s --existing-secret %s and reviewed artifact/release flags; never recreate or format for recovery", err, shellQuote(v.ID), shellQuote(p.Scope.Repo), shellQuote(o.Mount), shellQuote(recovery.Receipt.RecoveryReference()))
	}
	return err
}

func printStoragePrepared(outputOpts *outputOptions, out io.Writer, r storageReceipt) error {
	if outputOpts.outputFormat == "json" {
		return json.NewEncoder(out).Encode(map[string]any{"receipt": r, "configuration": "CONFIGURED_LOCAL", "detail": storageUnobserved, "unlock": "not_observed"})
	}
	fmt.Fprintf(out, "Volume: %s\nAuto-unlock: CONFIGURED_LOCAL\n%s\nConfig: %s\nPolicy: %s\n", r.VolumeID, storageUnobserved, r.ConfigPath, r.PolicyPath)
	fmt.Fprintf(out, "Review config, then propose: tinfoil repo config pr %s --file %s\nAfter review/merge: tinfoil repo build run %s --version %s\n", shellQuote(r.Profile.Scope.Repo), shellQuote(r.ConfigPath), shellQuote(r.Profile.Scope.Repo), shellQuote(r.Tag))
	fmt.Fprintln(out, "Wait for release workflows and publication. Independently review/merge/install the policy and restart your keyserver; no remote approval was performed.")
	fmt.Fprintln(out, "Deploy the exact repo/tag/domain with this original disk and --secret=\"\". The guest must finish its boot mount stage; no manual per-boot decrypt is needed.")
	return nil
}

func volumeStorageStatus(scope storageScope, id string) (string, string, error) {
	service, err := newStorageService()
	if err != nil {
		return "", "", err
	}
	return service.Status(scope, id)
}
