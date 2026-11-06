package cli

import (
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tinfoil-cli/internal/auth"
	"github.com/tinfoilsh/tinfoil-cli/internal/autounlock"
)

var (
	version          = defaultVersion
	cliTargets       = DefaultTargets
	clerkCLIClientID = DefaultClientID
	clerkCLIAPIScope = DefaultAPIScope
	clerkIssuer      = DefaultIssuer
	fixedAPIOrigin   = DefaultAPIOrigin
)

func executableAuthSettings() auth.BuildSettings {
	return auth.BuildSettings{Targets: cliTargets, ClientID: clerkCLIClientID, APIScope: clerkCLIAPIScope, Issuer: clerkIssuer, APIOrigin: fixedAPIOrigin}
}

func newRootCommand() *cobra.Command {
	settings := executableAuthSettings()
	return newRootCommandWithDependencies(commandDependencies{version: version, authSettings: &settings})
}

func testAccounts() *accountAccess { return testAccountsWithCredentials(auth.OSKeyring{}) }

func testAccountsWithCredentials(keyring auth.Keyring) *accountAccess {
	return newAccountAccess(executableAuthSettings(), version, func() (*auth.Store, error) {
		return credentialStore(keyring)
	}, nil)
}

func testAuthedClient(streams commandIO) (*cpClient, error) {
	return testAccounts().authedClient(streams)
}
func testScopeClient(streams commandIO) (accountScope, *cpClient, error) {
	return testAccounts().currentScope(streams)
}
func testCPClient(cfg cliConfig) *cpClient { return testAccounts().client(testStreams(), cfg) }
func requireAuth() (cliConfig, error)      { return testAccounts().requireAuth(testStreams()) }
func currentGrant() (*clerkGrant, error)   { return testAccounts().currentGrant(testStreams()) }
func authenticatedContext(cfg cliConfig) (authContext, error) {
	return testAccounts().authenticatedContext(testStreams(), cfg)
}
func clerkLogout(out io.Writer) error {
	streams := testStreams()
	streams.out = out
	return testAccounts().clerkLogout(streams)
}
func enrollRegistry(cmd *cobra.Command, cfg cliConfig, identity authContext, expected string, interactive bool) error {
	return testAccounts().enrollRegistry(cmd, cfg, identity, expected, interactive)
}

func testStreams() commandIO {
	return commandIO{in: os.Stdin, out: os.Stdout, err: os.Stderr}
}

func replaceTestCommand(root, replacement *cobra.Command) {
	for _, command := range root.Commands() {
		if command.Name() == replacement.Name() {
			replacement.GroupID = command.GroupID
			root.RemoveCommand(command)
		}
	}
	root.AddCommand(replacement)
}

type commandFixture struct {
	pollingOpts           *pollingOptions
	dependencies          commandDependencies
	attestSSHOpts         *attestSSHOptions
	attestationVerifyOpts *attestationVerifyOptions
	containerCancelOpts   *containerCancelOptions
	containerConnectOpts  *containerConnectOptions
	containerCreateOpts   *containerCreateOptions
	containerDeleteOpts   *containerDeleteOptions
	containerDeployOpts   *containerDeployOptions
	containerMetricsOpts  *containerMetricsOptions
	containerUpdateOpts   *containerUpdateOptions
	forwardOpts           *forwardOptions
	headersOpts           *headersOptions
	httpPostOpts          *httpPostOptions
	identityOpts          *identityOptions
	modelListOpts         *modelListOptions
	modelStatusOpts       *modelStatusOptions
	modelUpdateOpts       *modelUpdateOptions
	modelWrapOpts         *modelWrapOptions
	outputOpts            *outputOptions
	projectSettingsOpts   *projectSettingsOptions
	projectUpdateOpts     *projectUpdateOptions
	proxyOpts             *proxyOptions
	registrySetOpts       *registrySetOptions
	repoBuildRunOpts      *repoBuildRunOptions
	repoBuildStatusOpts   *repoBuildStatusOptions
	repoConfigGetOpts     *repoConfigGetOptions
	repoConfigPROpts      *repoConfigPROptions
	rootOpts              *rootOptions
	sandboxActionOpts     *sandboxActionOptions
	secretValueOpts       *secretValueOptions
	sshOpts               *sshOptions
	sshKeyOpts            *sshKeyOptions
	sshKeyCreateOpts      *sshKeyCreateOptions
	trustOpts             *trustOptions
	trustEnrollOpts       *trustEnrollOptions
	trustSetOpts          *trustSetOptions
	tunnelOpts            *tunnelOptions
	volumeAttachOpts      *volumeAttachOptions
	volumeCreateOpts      *volumeCreateOptions
	volumeDeleteOpts      *volumeDeleteOptions
	volumeRenameOpts      *volumeRenameOptions
	waitOpts              *waitOptions
	attestSSHCmd          *cobra.Command
	attestationCmd        *cobra.Command
	attestationVerifyCmd  *cobra.Command
	containerCancelCmd    *cobra.Command
	containerCmd          *cobra.Command
	containerConnectCmd   *cobra.Command
	containerCreateCmd    *cobra.Command
	containerDeleteCmd    *cobra.Command
	containerDeployCmd    *cobra.Command
	containerGetCmd       *cobra.Command
	containerHostsCmd     *cobra.Command
	containerListCmd      *cobra.Command
	containerMetricsCmd   *cobra.Command
	containerPromoteCmd   *cobra.Command
	containerStopCmd      *cobra.Command
	containerUpdateCmd    *cobra.Command
	domainAddCmd          *cobra.Command
	domainCmd             *cobra.Command
	domainDeleteCmd       *cobra.Command
	domainListCmd         *cobra.Command
	domainVerifyCmd       *cobra.Command
	forwardCmd            *cobra.Command
	httpCmd               *cobra.Command
	httpGetCmd            *cobra.Command
	httpPostCmd           *cobra.Command
	loginCmd              *cobra.Command
	logoutCmd             *cobra.Command
	modelCmd              *cobra.Command
	modelDeleteCmd        *cobra.Command
	modelListCmd          *cobra.Command
	modelStatusCmd        *cobra.Command
	modelUpdateCmd        *cobra.Command
	modelWrapCmd          *cobra.Command
	monitorCmd            *cobra.Command
	projectCmd            *cobra.Command
	projectGetCmd         *cobra.Command
	projectListCmd        *cobra.Command
	projectSettingsCmd    *cobra.Command
	projectUpdateCmd      *cobra.Command
	proxyCmd              *cobra.Command
	registryCmd           *cobra.Command
	registryDeleteCmd     *cobra.Command
	registryListCmd       *cobra.Command
	registrySetCmd        *cobra.Command
	repoBuildCmd          *cobra.Command
	repoBuildInfoCmd      *cobra.Command
	repoBuildRunCmd       *cobra.Command
	repoBuildStatusCmd    *cobra.Command
	repoCmd               *cobra.Command
	repoConfigCmd         *cobra.Command
	repoConfigGetCmd      *cobra.Command
	repoConfigPRCmd       *cobra.Command
	repoPRCmd             *cobra.Command
	repoPRStatusCmd       *cobra.Command
	repoSecretCmd         *cobra.Command
	repoSecretCreateCmd   *cobra.Command
	repoSecretDeleteCmd   *cobra.Command
	repoSecretGetCmd      *cobra.Command
	repoSecretListCmd     *cobra.Command
	repoSecretSetCmd      *cobra.Command
	rootCmd               *cobra.Command
	sandboxCmd            *cobra.Command
	sandboxDeleteCmd      *cobra.Command
	sandboxRestartCmd     *cobra.Command
	sandboxStartCmd       *cobra.Command
	sandboxStatusCmd      *cobra.Command
	sandboxStopCmd        *cobra.Command
	secretCmd             *cobra.Command
	secretCreateCmd       *cobra.Command
	secretDeleteCmd       *cobra.Command
	secretGetCmd          *cobra.Command
	secretListCmd         *cobra.Command
	secretSetCmd          *cobra.Command
	sshCmd                *cobra.Command
	sshKeyCmd             *cobra.Command
	sshKeyCreateCmd       *cobra.Command
	sshKeyDeleteCmd       *cobra.Command
	sshKeyListCmd         *cobra.Command
	trustCmd              *cobra.Command
	trustEnrollCmd        *cobra.Command
	trustRemoveCmd        *cobra.Command
	trustSetCmd           *cobra.Command
	volumeAttachCmd       *cobra.Command
	volumeCmd             *cobra.Command
	volumeCreateCmd       *cobra.Command
	volumeDeleteCmd       *cobra.Command
	volumeDetachCmd       *cobra.Command
	volumeGetCmd          *cobra.Command
	volumeListCmd         *cobra.Command
	volumeRenameCmd       *cobra.Command
	whoamiCmd             *cobra.Command
}

func newCommandFixture() *commandFixture {
	f := &commandFixture{
		pollingOpts:           defaultPollingOptions(),
		attestSSHOpts:         &attestSSHOptions{},
		attestationVerifyOpts: &attestationVerifyOptions{},
		containerCancelOpts:   &containerCancelOptions{},
		containerConnectOpts:  &containerConnectOptions{},
		containerCreateOpts:   &containerCreateOptions{},
		containerDeleteOpts:   &containerDeleteOptions{},
		containerDeployOpts:   &containerDeployOptions{},
		containerMetricsOpts:  &containerMetricsOptions{},
		containerUpdateOpts:   &containerUpdateOptions{},
		forwardOpts:           &forwardOptions{},
		headersOpts:           &headersOptions{},
		httpPostOpts:          &httpPostOptions{},
		identityOpts:          &identityOptions{},
		modelListOpts:         &modelListOptions{},
		modelStatusOpts:       &modelStatusOptions{},
		modelUpdateOpts:       &modelUpdateOptions{},
		modelWrapOpts:         &modelWrapOptions{},
		outputOpts:            &outputOptions{},
		projectSettingsOpts:   &projectSettingsOptions{},
		projectUpdateOpts:     &projectUpdateOptions{},
		proxyOpts:             &proxyOptions{},
		registrySetOpts:       &registrySetOptions{},
		repoBuildRunOpts:      &repoBuildRunOptions{},
		repoBuildStatusOpts:   &repoBuildStatusOptions{},
		repoConfigGetOpts:     &repoConfigGetOptions{},
		repoConfigPROpts:      &repoConfigPROptions{},
		rootOpts:              &rootOptions{registryOrigin: func() (string, error) { return testAccounts().registryControlplaneURL(testStreams()) }},
		sandboxActionOpts:     &sandboxActionOptions{},
		secretValueOpts:       &secretValueOptions{},
		sshOpts:               &sshOptions{},
		sshKeyOpts:            &sshKeyOptions{},
		sshKeyCreateOpts:      &sshKeyCreateOptions{},
		trustOpts:             &trustOptions{},
		trustEnrollOpts:       &trustEnrollOptions{},
		trustSetOpts:          &trustSetOptions{},
		tunnelOpts:            &tunnelOptions{},
		volumeAttachOpts:      &volumeAttachOptions{},
		volumeCreateOpts:      &volumeCreateOptions{},
		volumeDeleteOpts:      &volumeDeleteOptions{},
		volumeRenameOpts:      &volumeRenameOptions{},
		waitOpts:              &waitOptions{},
	}
	f.attestSSHCmd = newAttestSSHCommand(testAuthedClient, testScopeClient, f.attestSSHOpts, f.forwardOpts, f.identityOpts, f.rootOpts, f.trustOpts)
	f.attestationCmd = newAttestationCommand(f.rootOpts)
	f.attestationVerifyCmd = newAttestationVerifyCommand(f.attestationVerifyOpts, f.rootOpts)
	f.containerCancelCmd = newContainerCancelCommand(testAuthedClient, f.containerCancelOpts)
	f.containerCmd = newContainerCommand(f.pollingOpts, testAuthedClient, f.outputOpts, f.rootOpts)
	f.containerConnectCmd = newContainerConnectCommand(testAuthedClient, f.containerConnectOpts, f.proxyOpts, f.rootOpts, f.trustOpts)
	f.containerCreateCmd = newContainerCreateCommand(f.pollingOpts, testAuthedClient, f.containerCreateOpts, f.outputOpts, f.rootOpts, f.waitOpts)
	f.containerDeleteCmd = newContainerDeleteCommand(testAuthedClient, f.containerDeleteOpts)
	f.containerDeployCmd = newContainerDeployCommand(f.pollingOpts, testAuthedClient, f.containerDeployOpts, f.outputOpts, f.waitOpts)
	f.containerGetCmd = newContainerGetCommand(testAuthedClient, f.outputOpts)
	f.containerHostsCmd = newContainerHostsCommand(testAuthedClient, f.outputOpts)
	f.containerListCmd = newContainerListCommand(testAuthedClient, f.outputOpts)
	f.containerMetricsCmd = newContainerMetricsCommand(testAuthedClient, f.containerMetricsOpts)
	f.containerPromoteCmd = newContainerPromoteCommand(f.pollingOpts, testAuthedClient, f.outputOpts, f.waitOpts)
	f.containerStopCmd = newContainerStopCommand(testAuthedClient, f.outputOpts)
	f.containerUpdateCmd = newContainerUpdateCommand(f.pollingOpts, testAuthedClient, f.containerUpdateOpts, f.outputOpts, f.waitOpts)
	f.domainAddCmd = newDomainAddCommand(testAuthedClient, f.outputOpts)
	f.domainCmd = newDomainCommand(testAuthedClient, f.outputOpts)
	f.domainDeleteCmd = newDomainDeleteCommand(testAuthedClient)
	f.domainListCmd = newDomainListCommand(testAuthedClient, f.outputOpts)
	f.domainVerifyCmd = newDomainVerifyCommand(testAuthedClient, f.outputOpts)
	f.forwardCmd = newForwardCommand(testAuthedClient, f.forwardOpts, f.rootOpts, f.trustOpts, f.tunnelOpts)
	f.httpCmd = newHttpCommand(f.headersOpts, f.rootOpts)
	f.httpGetCmd = newHttpGetCommand(f.headersOpts, f.rootOpts)
	f.httpPostCmd = newHttpPostCommand(f.headersOpts, f.httpPostOpts, f.rootOpts)
	f.loginCmd = newLoginCommand(testAccounts(), openBrowser)
	f.logoutCmd = newLogoutCommand(testAccounts())
	f.modelCmd = newModelCommand(f.pollingOpts, testAuthedClient, f.outputOpts)
	f.modelDeleteCmd = newModelDeleteCommand(testAuthedClient)
	f.modelListCmd = newModelListCommand(testAuthedClient, f.modelListOpts, f.outputOpts)
	f.modelStatusCmd = newModelStatusCommand(f.pollingOpts, testAuthedClient, f.modelStatusOpts, f.outputOpts)
	f.modelUpdateCmd = newModelUpdateCommand(f.pollingOpts, testAuthedClient, f.modelUpdateOpts, f.outputOpts)
	f.modelWrapCmd = newModelWrapCommand(f.pollingOpts, testAuthedClient, f.modelWrapOpts, f.outputOpts)
	f.monitorCmd = newMonitorCommand()
	f.projectCmd = newProjectCommand(testAuthedClient, f.outputOpts)
	f.projectGetCmd = newProjectGetCommand(testAuthedClient, f.outputOpts)
	f.projectListCmd = newProjectListCommand(testAuthedClient, f.outputOpts)
	f.projectSettingsCmd = newProjectSettingsCommand(testAuthedClient, f.outputOpts, f.projectSettingsOpts)
	f.projectUpdateCmd = newProjectUpdateCommand(testAuthedClient, f.outputOpts, f.projectUpdateOpts)
	f.proxyCmd = newProxyCommand(f.proxyOpts, f.rootOpts)
	f.registryCmd = newRegistryCommand(testAuthedClient, f.outputOpts)
	f.registryDeleteCmd = newRegistryDeleteCommand(testAuthedClient)
	f.registryListCmd = newRegistryListCommand(testAuthedClient, f.outputOpts)
	f.registrySetCmd = newRegistrySetCommand(testAuthedClient, f.registrySetOpts)
	f.repoBuildCmd = newRepoBuildCommand(testAuthedClient, f.outputOpts)
	f.repoBuildInfoCmd = newRepoBuildInfoCommand(testAuthedClient, f.outputOpts)
	f.repoBuildRunCmd = newRepoBuildRunCommand(testAuthedClient, f.outputOpts, f.repoBuildRunOpts)
	f.repoBuildStatusCmd = newRepoBuildStatusCommand(testAuthedClient, f.outputOpts, f.repoBuildStatusOpts)
	f.repoCmd = newRepoCommand(testAuthedClient, f.outputOpts)
	f.repoConfigCmd = newRepoConfigCommand(testAuthedClient, f.outputOpts)
	f.repoConfigGetCmd = newRepoConfigGetCommand(testAuthedClient, f.outputOpts, f.repoConfigGetOpts)
	f.repoConfigPRCmd = newRepoConfigPRCommand(testAuthedClient, f.outputOpts, f.repoConfigPROpts)
	f.repoPRCmd = newRepoPRCommand(testAuthedClient, f.outputOpts)
	f.repoPRStatusCmd = newRepoPRStatusCommand(testAuthedClient, f.outputOpts)
	f.repoSecretCmd = newRepoSecretCommand(testAuthedClient, f.outputOpts)
	f.repoSecretCreateCmd = newRepoSecretCreateCommand(testAuthedClient, f.secretValueOpts)
	f.repoSecretDeleteCmd = newRepoSecretDeleteCommand(testAuthedClient)
	f.repoSecretGetCmd = newRepoSecretGetCommand(testAuthedClient, f.outputOpts)
	f.repoSecretListCmd = newRepoSecretListCommand(testAuthedClient, f.outputOpts)
	f.repoSecretSetCmd = newRepoSecretSetCommand(testAuthedClient, f.secretValueOpts)
	f.rootCmd = newRootCommand()
	f.sandboxCmd = newSandboxCommand(f.pollingOpts, testAuthedClient, testScopeClient, f.identityOpts, f.outputOpts, f.rootOpts)
	f.sandboxDeleteCmd = newSandboxDeleteCommand(f.pollingOpts, testAuthedClient, testScopeClient, f.identityOpts, f.outputOpts, f.rootOpts, f.sandboxActionOpts, f.trustOpts)
	f.sandboxRestartCmd = newSandboxRestartCommand(f.pollingOpts, testAuthedClient, testScopeClient, f.identityOpts, f.outputOpts, f.rootOpts, f.sandboxActionOpts, f.trustOpts)
	f.sandboxStartCmd = newSandboxStartCommand(f.pollingOpts, testAuthedClient, testScopeClient, f.identityOpts, f.outputOpts, f.rootOpts, f.sandboxActionOpts, f.trustOpts)
	f.sandboxStatusCmd = newSandboxStatusCommand(f.pollingOpts, testAuthedClient, f.outputOpts)
	f.sandboxStopCmd = newSandboxStopCommand(f.pollingOpts, testAuthedClient, testScopeClient, f.identityOpts, f.outputOpts, f.rootOpts, f.sandboxActionOpts, f.trustOpts)
	f.secretCmd = newSecretCommand(testAuthedClient, f.outputOpts)
	f.secretCreateCmd = newSecretCreateCommand(testAuthedClient, f.secretValueOpts)
	f.secretDeleteCmd = newSecretDeleteCommand(testAuthedClient)
	f.secretGetCmd = newSecretGetCommand(testAuthedClient, f.outputOpts)
	f.secretListCmd = newSecretListCommand(testAuthedClient, f.outputOpts)
	f.secretSetCmd = newSecretSetCommand(testAuthedClient, f.secretValueOpts)
	f.sshCmd = newSshCommand(testAuthedClient, f.forwardOpts, f.rootOpts, f.sshOpts, f.trustOpts, f.tunnelOpts)
	f.sshKeyCmd = newSshKeyCommand(testAuthedClient, f.outputOpts, f.sshKeyOpts)
	f.sshKeyCreateCmd = newSshKeyCreateCommand(testAuthedClient, f.sshKeyOpts, f.sshKeyCreateOpts)
	f.sshKeyDeleteCmd = newSshKeyDeleteCommand(testAuthedClient, f.sshKeyOpts)
	f.sshKeyListCmd = newSshKeyListCommand(testAuthedClient, f.outputOpts, f.sshKeyOpts)
	f.trustCmd = newTrustCommand(testAccounts(), f.trustOpts)
	f.trustEnrollCmd = newTrustEnrollCommand(testAccounts(), f.trustEnrollOpts)
	f.trustRemoveCmd = newTrustRemoveCommand(testAccounts())
	f.trustSetCmd = newTrustSetCommand(f.trustSetOpts)
	f.volumeAttachCmd = newVolumeAttachCommand(testAuthedClient, f.volumeAttachOpts)
	f.volumeCmd = newVolumeCommand(testAuthedClient, autounlock.NewAWSKeyStore, f.outputOpts)
	f.volumeCreateCmd = newVolumeCreateCommand(testAuthedClient, autounlock.NewAWSKeyStore, f.outputOpts, f.volumeCreateOpts)
	f.volumeDeleteCmd = newVolumeDeleteCommand(testAuthedClient, f.volumeDeleteOpts)
	f.volumeDetachCmd = newVolumeDetachCommand(testAuthedClient)
	f.volumeGetCmd = newVolumeGetCommand(testAuthedClient, f.outputOpts)
	f.volumeListCmd = newVolumeListCommand(testAuthedClient, f.outputOpts)
	f.volumeRenameCmd = newVolumeRenameCommand(testAuthedClient, f.volumeRenameOpts)
	f.whoamiCmd = newWhoamiCommand(testAccounts())
	return f
}
