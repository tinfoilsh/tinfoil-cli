package main

import (
	"os"

	"github.com/spf13/cobra"
)

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
		rootOpts:              &rootOptions{},
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
	f.attestSSHCmd = newAttestSSHCommand(f.attestSSHOpts, f.forwardOpts, f.identityOpts, f.rootOpts, f.trustOpts)
	f.attestationCmd = newAttestationCommand(f.rootOpts)
	f.attestationVerifyCmd = newAttestationVerifyCommand(f.attestationVerifyOpts, f.rootOpts)
	f.containerCancelCmd = newContainerCancelCommand(f.containerCancelOpts)
	f.containerCmd = newContainerCommand(f.outputOpts, f.rootOpts)
	f.containerConnectCmd = newContainerConnectCommand(f.containerConnectOpts, f.proxyOpts, f.rootOpts, f.trustOpts)
	f.containerCreateCmd = newContainerCreateCommand(f.containerCreateOpts, f.outputOpts, f.rootOpts, f.waitOpts)
	f.containerDeleteCmd = newContainerDeleteCommand(f.containerDeleteOpts)
	f.containerDeployCmd = newContainerDeployCommand(f.containerDeployOpts, f.outputOpts, f.waitOpts)
	f.containerGetCmd = newContainerGetCommand(f.outputOpts)
	f.containerHostsCmd = newContainerHostsCommand(f.outputOpts)
	f.containerListCmd = newContainerListCommand(f.outputOpts)
	f.containerMetricsCmd = newContainerMetricsCommand(f.containerMetricsOpts)
	f.containerPromoteCmd = newContainerPromoteCommand(f.outputOpts, f.waitOpts)
	f.containerStopCmd = newContainerStopCommand(f.outputOpts)
	f.containerUpdateCmd = newContainerUpdateCommand(f.containerUpdateOpts, f.outputOpts, f.waitOpts)
	f.domainAddCmd = newDomainAddCommand(f.outputOpts)
	f.domainCmd = newDomainCommand(f.outputOpts)
	f.domainDeleteCmd = newDomainDeleteCommand()
	f.domainListCmd = newDomainListCommand(f.outputOpts)
	f.domainVerifyCmd = newDomainVerifyCommand(f.outputOpts)
	f.forwardCmd = newForwardCommand(f.forwardOpts, f.rootOpts, f.trustOpts, f.tunnelOpts)
	f.httpCmd = newHttpCommand(f.headersOpts, f.rootOpts)
	f.httpGetCmd = newHttpGetCommand(f.headersOpts, f.rootOpts)
	f.httpPostCmd = newHttpPostCommand(f.headersOpts, f.httpPostOpts, f.rootOpts)
	f.loginCmd = newLoginCommand(openBrowser)
	f.logoutCmd = newLogoutCommand()
	f.modelCmd = newModelCommand(f.outputOpts)
	f.modelDeleteCmd = newModelDeleteCommand()
	f.modelListCmd = newModelListCommand(f.modelListOpts, f.outputOpts)
	f.modelStatusCmd = newModelStatusCommand(f.modelStatusOpts, f.outputOpts)
	f.modelUpdateCmd = newModelUpdateCommand(f.modelUpdateOpts, f.outputOpts)
	f.modelWrapCmd = newModelWrapCommand(f.modelWrapOpts, f.outputOpts)
	f.monitorCmd = newMonitorCommand()
	f.projectCmd = newProjectCommand(f.outputOpts)
	f.projectGetCmd = newProjectGetCommand(f.outputOpts)
	f.projectListCmd = newProjectListCommand(f.outputOpts)
	f.projectSettingsCmd = newProjectSettingsCommand(f.outputOpts, f.projectSettingsOpts)
	f.projectUpdateCmd = newProjectUpdateCommand(f.outputOpts, f.projectUpdateOpts)
	f.proxyCmd = newProxyCommand(f.proxyOpts, f.rootOpts)
	f.registryCmd = newRegistryCommand(f.outputOpts)
	f.registryDeleteCmd = newRegistryDeleteCommand()
	f.registryListCmd = newRegistryListCommand(f.outputOpts)
	f.registrySetCmd = newRegistrySetCommand(f.registrySetOpts)
	f.repoBuildCmd = newRepoBuildCommand(f.outputOpts)
	f.repoBuildInfoCmd = newRepoBuildInfoCommand(f.outputOpts)
	f.repoBuildRunCmd = newRepoBuildRunCommand(f.outputOpts, f.repoBuildRunOpts)
	f.repoBuildStatusCmd = newRepoBuildStatusCommand(f.outputOpts, f.repoBuildStatusOpts)
	f.repoCmd = newRepoCommand(f.outputOpts)
	f.repoConfigCmd = newRepoConfigCommand(f.outputOpts)
	f.repoConfigGetCmd = newRepoConfigGetCommand(f.outputOpts, f.repoConfigGetOpts)
	f.repoConfigPRCmd = newRepoConfigPRCommand(f.outputOpts, f.repoConfigPROpts)
	f.repoPRCmd = newRepoPRCommand(f.outputOpts)
	f.repoPRStatusCmd = newRepoPRStatusCommand(f.outputOpts)
	f.repoSecretCmd = newRepoSecretCommand(f.outputOpts)
	f.repoSecretCreateCmd = newRepoSecretCreateCommand(f.secretValueOpts)
	f.repoSecretDeleteCmd = newRepoSecretDeleteCommand()
	f.repoSecretGetCmd = newRepoSecretGetCommand(f.outputOpts)
	f.repoSecretListCmd = newRepoSecretListCommand(f.outputOpts)
	f.repoSecretSetCmd = newRepoSecretSetCommand(f.secretValueOpts)
	f.rootCmd = newRootCommand()
	f.sandboxCmd = newSandboxCommand(f.identityOpts, f.outputOpts, f.rootOpts)
	f.sandboxDeleteCmd = newSandboxDeleteCommand(f.identityOpts, f.outputOpts, f.rootOpts, f.sandboxActionOpts, f.trustOpts)
	f.sandboxRestartCmd = newSandboxRestartCommand(f.identityOpts, f.outputOpts, f.rootOpts, f.sandboxActionOpts, f.trustOpts)
	f.sandboxStartCmd = newSandboxStartCommand(f.identityOpts, f.outputOpts, f.rootOpts, f.sandboxActionOpts, f.trustOpts)
	f.sandboxStatusCmd = newSandboxStatusCommand(f.outputOpts)
	f.sandboxStopCmd = newSandboxStopCommand(f.identityOpts, f.outputOpts, f.rootOpts, f.sandboxActionOpts, f.trustOpts)
	f.secretCmd = newSecretCommand(f.outputOpts)
	f.secretCreateCmd = newSecretCreateCommand(f.secretValueOpts)
	f.secretDeleteCmd = newSecretDeleteCommand()
	f.secretGetCmd = newSecretGetCommand(f.outputOpts)
	f.secretListCmd = newSecretListCommand(f.outputOpts)
	f.secretSetCmd = newSecretSetCommand(f.secretValueOpts)
	f.sshCmd = newSshCommand(f.forwardOpts, f.rootOpts, f.sshOpts, f.trustOpts, f.tunnelOpts)
	f.sshKeyCmd = newSshKeyCommand(f.outputOpts, f.sshKeyOpts)
	f.sshKeyCreateCmd = newSshKeyCreateCommand(f.sshKeyOpts, f.sshKeyCreateOpts)
	f.sshKeyDeleteCmd = newSshKeyDeleteCommand(f.sshKeyOpts)
	f.sshKeyListCmd = newSshKeyListCommand(f.outputOpts, f.sshKeyOpts)
	f.trustCmd = newTrustCommand(f.trustOpts)
	f.trustEnrollCmd = newTrustEnrollCommand(f.trustEnrollOpts)
	f.trustRemoveCmd = newTrustRemoveCommand()
	f.trustSetCmd = newTrustSetCommand(f.trustSetOpts)
	f.volumeAttachCmd = newVolumeAttachCommand(f.volumeAttachOpts)
	f.volumeCmd = newVolumeCommand(f.outputOpts)
	f.volumeCreateCmd = newVolumeCreateCommand(f.outputOpts, f.volumeCreateOpts)
	f.volumeDeleteCmd = newVolumeDeleteCommand(f.volumeDeleteOpts)
	f.volumeDetachCmd = newVolumeDetachCommand()
	f.volumeGetCmd = newVolumeGetCommand(f.outputOpts)
	f.volumeListCmd = newVolumeListCommand(f.outputOpts)
	f.volumeRenameCmd = newVolumeRenameCommand(f.volumeRenameOpts)
	f.whoamiCmd = newWhoamiCommand()
	return f
}
