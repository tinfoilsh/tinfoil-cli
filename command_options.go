package main

import (
	"context"
	"io"
	"net/http"

	"github.com/tinfoilsh/tinfoil-cli/internal/auth"
)

type attestSSHOptions struct {
	attestSSHHost    string
	attestSSHInstall bool
	attestSSHName    string
	attestSSHPort    uint
	attestSSHUser    string
	attestSSHYes     bool
}

type attestationVerifyOptions struct {
	jsonFile   string
	jsonOutput bool
}

type containerCancelOptions struct {
	cancelRollbackLatest bool
}

type containerConnectOptions struct {
	connectBindAddr string
	connectPort     uint
	connectReview   bool
}

type containerCreateOptions struct {
	createCustomDomain      string
	createDebug             bool
	createDisableCC         bool
	createDisplayOrder      int32
	createHost              string
	createMarkLatestRelease string
	createReplaceID         string
	createRepo              string
	createRevision          string
	createSSHKeys           []string
	createSecrets           []string
	createSource            string
	createTag               string
	createVariables         []string
	createVolumes           []string
	createYes               bool
}

type containerDeleteOptions struct {
	deleteYes bool
}

type containerDeployOptions struct {
	deployCustomDomain      string
	deployDebug             string
	deployHost              string
	deployMarkLatestRelease string
	deploySSHKeys           []string
	deploySecrets           []string
	deployTag               string
	deployVariables         []string
	deployVolumes           []string
}

type containerMetricsOptions struct {
	metricsTime string
}

type containerUpdateOptions struct {
	updateCustomDomain      string
	updateDebug             string
	updateHold              string
	updateMarkLatestRelease string
	updateSSHKeys           []string
	updateSecrets           []string
	updateTag               string
	updateVariables         []string
	updateYes               bool
}

type forwardOptions struct {
	forwardPorts    []string
	forwardSealedTo string
	forwardStdio    uint
}

type headersOptions struct {
	requestHeaders []string
}

type httpPostOptions struct {
	body   string
	stream bool
}

type identityOptions struct {
	attestSSHIdentity string
}

type modelListOptions struct {
	modelListLimit int
}

type modelStatusOptions struct {
	modelStatusLogs bool
	modelStatusWait bool
}

type modelUpdateOptions struct {
	modelUpdateCommit      string
	modelUpdateHFToken     string
	modelUpdateHFTokenFile string
	modelUpdateHost        string
	modelUpdateWait        bool
}

type modelWrapOptions struct {
	modelWrapCommit      string
	modelWrapHFToken     string
	modelWrapHFTokenFile string
	modelWrapHost        string
	modelWrapWait        bool
}

type outputOptions struct {
	outputFormat string
}

type projectSettingsOptions struct {
	projectSettingsHoldByDefault string
}

type projectUpdateOptions struct {
	projectUpdateHold              string
	projectUpdateInstanceIDs       []string
	projectUpdateMarkLatestRelease string
	projectUpdateTag               string
	projectUpdateYes               bool
}

type proxyOptions struct {
	listenAddr string
	listenPort uint
	logFormat  string
}

type registrySetOptions struct {
	registryKeyFile  string
	registryToken    string
	registryUsername string
}

type repoBuildRunOptions struct {
	repoVersion string
}

type repoBuildStatusOptions struct {
	repoStatusVersion string
}

type repoConfigGetOptions struct {
	repoConfigRaw bool
}

type repoConfigPROptions struct {
	repoConfigFile string
	repoPRBody     string
}

type rootOptions struct {
	registryOrigin   func() (string, error)
	connections      connectionDependencies
	enclaveHost      string
	localConfigBytes []byte
	localConfigFile  string
	publicRegistry   bool
	repo             string
	trace            bool
	verbose          bool
}

type sandboxEvidenceVerifier func(doc, nonce []byte, source string) (attestedEvidence, error)

type connectionDependencies struct {
	proxyClient           func(context.Context, string, string) (*http.Client, error)
	serveProxy            func(string, http.Handler) error
	verifySandboxEvidence sandboxEvidenceVerifier
}

type commandDependencies struct {
	volumeStore           storageStoreFactory
	authSettings          *auth.BuildSettings
	credentials           credentialStoreFactory
	accountHTTP           *http.Client
	version               string
	updateTransport       http.RoundTripper
	in                    io.Reader
	out                   io.Writer
	err                   io.Writer
	proxyClient           func(context.Context, string, string) (*http.Client, error)
	serveProxy            func(string, http.Handler) error
	openBrowser           func(string) error
	verifySandboxEvidence sandboxEvidenceVerifier
}

func (d commandDependencies) browser() func(string) error {
	if d.openBrowser != nil {
		return d.openBrowser
	}
	return openBrowser
}

type sandboxActionOptions struct {
	sandboxYes bool
}

type secretValueOptions struct {
	secretValue     string
	secretValueFile string
}

type sshOptions struct {
	sshPort uint
	sshUser string
}

type sshKeyOptions struct {
	sshKeySandbox bool
}

type sshKeyCreateOptions struct {
	sshPublicKey     string
	sshPublicKeyFile string
}

type trustOptions struct {
	trustDangerous bool
	trustJSON      bool
}

type trustEnrollOptions struct {
	enrollmentRegistryID string
}

type trustSetOptions struct {
	trustSetMode   string
	trustSetPrune  bool
	trustSetRecord string
}

type tunnelOptions struct {
	allowDebug   bool
	tunnelAPIKey string
}

type volumeAttachOptions struct {
	volumeAttachAs string
}

type volumeCreateOptions struct {
	volumeCreateHost    string
	volumeCreateSandbox bool
	volumeCreateSize    string
}

type volumeDeleteOptions struct {
	volumeYes bool
}

type volumeRenameOptions struct {
	volumeRenameName string
}

type waitOptions struct {
	noWait bool
}
