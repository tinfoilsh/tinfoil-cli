package owner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-cli/internal/connection"
	"github.com/tinfoilsh/tinfoil-cli/internal/controlplane"
	"github.com/tinfoilsh/tinfoil-cli/internal/keybundle"
	"github.com/tinfoilsh/tinfoil-cli/internal/statefile"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"golang.org/x/crypto/ssh"
)

const envConfigPath = "TINFOIL_CONFIG"
const keyStatePath = controlplane.KeyStatePath
const monitorProfileFile = ProfileFile

type keyState = controlplane.KeyState
type keyStateWrite = controlplane.KeyStateWrite
type accountScope = Scope
type containerView = controlplane.Container
type monitorProfile = Profile
type sandboxSession = Sandbox
type monitorSession = Monitor
type containerNetworkPolicy = controlplane.NetworkPolicy
type containerPeer = controlplane.Peer
type containerAlias = controlplane.Alias

const statusRunning = "running"

func (s *Sandbox) enroll(ctx context.Context) error { return s.Enroll(ctx) }
func testSigner(t *testing.T) ssh.Signer {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	return signer
}
func testHostKey(t *testing.T) ssh.PublicKey { return testSigner(t).PublicKey() }
func authorizedLine(signer ssh.Signer) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}
func sendOwnerCommand(ctx context.Context, dial func(context.Context) (*ssh.Client, error), command string, body []byte) (string, error) {
	return SendCommand(ctx, dial, command, body)
}
func connectOwnerSigner(conn net.Conn, host string, hostKey ssh.PublicKey, signer ssh.Signer, user string) (*ssh.Client, error) {
	return Connect(conn, host, hostKey, signer, user)
}

type relayVerifier func(source string, doc, nonce []byte) (connection.Evidence, error)

func (f relayVerifier) RelayEvidence(source string, doc, nonce []byte) (connection.Evidence, error) {
	return f(source, doc, nonce)
}
func (f relayVerifier) MonitorHost(string, string) (ssh.PublicKey, error) {
	panic("unexpected Monitor verification")
}
func (f relayVerifier) DirectEvidence(context.Context, string, string) (connection.Evidence, error) {
	panic("unexpected direct verification")
}

type hostEvidence struct {
	host    ssh.PublicKey
	expires time.Time
}

func (e hostEvidence) FreshnessExpiresAt() time.Time { return e.expires }
func (e hostEvidence) CryptoMaterialData(id, format string) (string, bool) {
	if id != "host-ssh" || format != document.KeySPKIV1Format || e.host == nil {
		return "", false
	}
	der, err := x509.MarshalPKIXPublicKey(e.host.(ssh.CryptoPublicKey).CryptoPublicKey())
	return hex.EncodeToString(der), err == nil
}

type workloadTarget struct {
	containerView
	source string
	env    map[string]string
}
type cpClient struct {
	*controlplane.Client
	service *Service
}

var attestSSHIdentity string

func testService() *Service {
	return &Service{ConfigPath: os.Getenv(envConfigPath), Home: os.UserHomeDir, IdentityFile: attestSSHIdentity, AgentSocket: os.Getenv("SSH_AUTH_SOCK")}
}
func newMKSession(cp *cpClient, scope Scope) (*mkSession, error) {
	return cp.service.newMKSession(cp.Client, scope)
}
func resolveResourceKeys(ctx context.Context, cp *cpClient, scope Scope, row containerView, kind string, binding mkBinding, dir string, bind bool) (*resourceKeys, error) {
	service := *cp.service
	service.Home, service.IdentityFile, service.AgentSocket = os.UserHomeDir, attestSSHIdentity, os.Getenv("SSH_AUTH_SOCK")
	return service.resolveResourceKeys(ctx, cp.Client, scope, row, kind, binding, dir, bind)
}
func saveUMKRecord(path string, record *umkRecord) (*umkRecord, error) {
	return testService().saveUMKRecord(path, record)
}
func resourceDir(scope Scope, id, name string) (string, error) {
	return resourceDirectory(os.Getenv(envConfigPath), scope, id, name)
}
func umkRecordPath(scope Scope, id string) (string, error) {
	return umkPath(os.Getenv(envConfigPath), scope, id)
}
func monitorRecord(scope Scope, row *workloadTarget) (string, error) {
	return testService().monitorRecord(scope, &Workload{Container: row.containerView, Source: row.source, Environment: row.env})
}
func userSigner(name, owner, dir string) (ssh.Signer, string, func(), error) {
	return testService().userSigner(name, owner, dir)
}
func storageHash(data []byte) string             { return hash(data) }
func readStorageJSON(path string, out any) error { return statefile.ReadJSON(path, out) }
func writeStorageJSON(path string, v any, exclusive bool) error {
	return statefile.WriteJSON(path, v, exclusive)
}
func sealMK(p *mkPayload, dek []byte, c mkContext) (string, error) { return keybundle.Seal(p, dek, c) }
func openMK(envelope string, dek []byte, c mkContext) (*mkPayload, error) {
	return keybundle.Open(envelope, dek, c)
}
func ed25519PublicKeyString(seed []byte) string { return keybundle.PublicKeyString(seed) }
