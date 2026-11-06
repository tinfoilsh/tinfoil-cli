package owner

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-cli/internal/connection"
	"github.com/tinfoilsh/tinfoil-cli/internal/controlplane"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"golang.org/x/crypto/ssh"
)

func TestSandboxAttestationRelayUsesCurrentSchema(t *testing.T) {
	const instance = "22222222-2222-4222-8222-222222222222"
	const source = "acme/sandbox@v1"
	doc := []byte("attestation document")
	challenges := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			InstanceID string `json:"instance_id"`
			Nonce      string `json:"nonce"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		nonce, err := hex.DecodeString(input.Nonce)
		if r.Method != http.MethodPost || r.URL.Path != "/sandboxes/relay" || input.InstanceID != instance || err != nil || len(nonce) != document.NonceSize {
			http.Error(w, "invalid attestation relay request", http.StatusBadRequest)
			return
		}
		challenges <- nonce
		json.NewEncoder(w).Encode(map[string]any{"status": http.StatusOK, "body": base64.RawURLEncoding.EncodeToString(doc)})
	}))
	defer server.Close()
	client := controlplane.New(server.URL, "test", server.Client(), nil)
	owner := sandboxOwner{instance: instance, request: func(method, path string, input, out any) error {
		_, err := client.Do(t.Context(), method, path, nil, nil, input, out)
		return err
	}}
	verificationError := errors.New("verification stopped")
	verifier := relayVerifier(func(reference string, raw, nonce []byte) (connection.Evidence, error) {
		require.Equal(t, doc, raw)
		require.Equal(t, <-challenges, nonce)
		require.Equal(t, source, reference)
		return nil, verificationError
	})
	_, err := owner.attest(source, verifier)
	require.ErrorIs(t, err, verificationError)
}

type fakeOwnerTransport struct {
	status sandboxStatus
	calls  []string
	bodies map[string]json.RawMessage
}

func (f *fakeOwnerTransport) reply(request ownerCall) any {
	f.calls = append(f.calls, request.Method+" "+request.Path)
	if f.bodies == nil {
		f.bodies = map[string]json.RawMessage{}
	}
	f.bodies[request.Path] = request.Body
	if request.Path == "/enroll" {
		var in struct {
			MonitorIdentitySeed b64u   `json:"monitor_identity_seed"`
			MonitorHostKey      string `json:"monitor_host_key"`
		}
		json.Unmarshal(request.Body, &in)
		agent := monitorIdentity(in.MonitorIdentitySeed)
		f.status.MonitorIdentity, f.status.MonitorHostKey, f.status.Volume = &agent, &in.MonitorHostKey, "unlocked"
	}
	return f.status
}

func TestSandboxEnrollDecidesFromMonitorIdentityAndSandboxStatus(t *testing.T) {
	instance := "22222222-2222-4222-8222-222222222222"
	volume := "33333333-3333-4333-8333-333333333333"
	monitorIdentitySeed, otherSeed := testSeed(t), testSeed(t)
	agent, other := monitorIdentity(monitorIdentitySeed), monitorIdentity(otherSeed)
	monitorHost, oldHost := testSigner(t).PublicKey(), authorizedLine(testSigner(t))
	host := authorizedKeyLine(monitorHost)
	for _, test := range []struct {
		name          string
		agent         *string
		volume        string
		pinned        *string
		monitorKnows  bool
		noLocalKeys   bool
		monitorEnroll bool
		calls         []string
		initialize    bool
		err           string
	}{
		{name: "first open", volume: "locked", monitorEnroll: true, calls: []string{"GET /status", "POST /enroll"}, initialize: true},
		{name: "rebooted sandbox", volume: "locked", monitorKnows: true, calls: []string{"GET /status", "POST /enroll"}, initialize: true},
		{name: "removed identity after Monitor-only restart", agent: &agent, volume: "unlocked", pinned: &oldHost, calls: []string{"GET /status"}, err: "no longer authorizes"},
		{name: "Monitor-only restart", agent: &agent, volume: "unlocked", pinned: &oldHost, monitorKnows: true, calls: []string{"GET /status", "POST /enroll"}, initialize: true},
		{name: "interrupted unlock", agent: &agent, volume: "locked", pinned: &host, monitorKnows: true, calls: []string{"GET /status", "POST /enroll"}, initialize: true},
		{name: "already enrolled", agent: &agent, volume: "unlocked", pinned: &host, monitorKnows: true, calls: []string{"GET /status"}},
		{name: "another identity", agent: &other, volume: "unlocked", monitorKnows: true, calls: []string{"GET /status"}, err: "different Monitor identity"},
		{name: "web-provisioned UMK", volume: "locked", noLocalKeys: true, monitorEnroll: true, calls: []string{"GET /status", "POST /enroll"}, initialize: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
			seed := testSeed(t)
			signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
			require.NoError(t, err)
			owner := ed25519PublicKeyString(seed)
			transport := &fakeOwnerTransport{status: sandboxStatus{Protocol: sandboxOwnerProtocol, InstanceID: instance, Volume: test.volume, MonitorIdentity: test.agent, MonitorHostKey: test.pinned}}
			rpc, endpoint := testSandboxOwner(t, seed, transport.reply)
			rpc.instance = instance
			var monitorCalls []string
			m := &monitorSession{dir: t.TempDir(), hostKey: monitorHost, keys: &resourceKeys{}}
			if test.monitorKnows {
				m.view.Config.Identities = map[string]struct {
					Key string `json:"key"`
				}{"sandbox-work": {Key: agent}}
			}
			m.request = func(method, path string, input, out any) error {
				data, _ := json.Marshal(input)
				monitorCalls = append(monitorCalls, method+" "+path+" "+string(data))
				return nil
			}
			keys := &resourceKeys{mode: "tmk", signer: signer, monitorIdentitySeed: bytes.Clone(monitorIdentitySeed), storageKey: testSeed(t)}
			scope := accountScope{ControlplaneURL: "https://cp.example", UserID: "user_owner"}
			if test.noLocalKeys {
				keys = &resourceKeys{service: testService(), mode: "umk", signer: signer}
				keys.umkPath, err = umkRecordPath(scope, "11111111-1111-4111-8111-111111111111")
				require.NoError(t, err)
			}
			s := &sandboxSession{box: containerView{Name: "work", OwnerPublicKey: owner}, keys: keys, monitor: m, expires: time.Now().Add(time.Hour),
				binding: mkBinding{Account: "personal", ContainerID: "11111111-1111-4111-8111-111111111111", InstanceID: &instance, VolumeID: &volume},
				owner:   rpc}
			err = s.enroll(t.Context())
			endpoint.mu.Lock()
			defer endpoint.mu.Unlock()
			if test.err != "" {
				require.ErrorContains(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, test.calls, transport.calls)
			require.Equal(t, test.monitorEnroll, len(monitorCalls) == 1, "Monitor calls: %v", monitorCalls)
			if test.monitorEnroll {
				enrolled := agent
				if test.noLocalKeys {
					enrolled = monitorIdentity(keys.monitorIdentitySeed)
				}
				require.Equal(t, `POST /enroll {"sandbox-work":{"key":"`+enrolled+`"}}`, monitorCalls[0], "only the public agent key goes to Monitor, never restored")
			}
			if enroll, ok := transport.bodies["/enroll"]; ok {
				var in struct {
					MonitorIdentitySeed b64u   `json:"monitor_identity_seed"`
					MonitorHostKey      string `json:"monitor_host_key"`
					DiskKey             b64u   `json:"disk_key"`
					AllowInitialize     bool   `json:"allow_initialize"`
				}
				require.NoError(t, json.Unmarshal(enroll, &in))
				require.Equal(t, test.initialize, in.AllowInitialize)
				require.Equal(t, host, in.MonitorHostKey)
				require.Equal(t, []byte(keys.storageKey), []byte(in.DiskKey))
			}
			_, statErr := os.Stat(keys.umkPath)
			require.Equal(t, test.noLocalKeys && test.err == "", statErr == nil, "UMK keys are generated only when missing")
		})
	}
}

func TestDirectProfileUnlocksOverAttestedOwnerSSH(t *testing.T) {
	seed := testSeed(t)
	host := testSigner(t)
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(host)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	type invocation struct {
		command string
		body    []byte
	}
	calls := make(chan invocation, 16)
	var volume atomic.Value
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				server, channels, global, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(global)
				channel, pending, err := (<-channels).Accept()
				if err != nil {
					return
				}
				defer channel.Close()
				request := <-pending
				var command struct{ Command string }
				if request.Type != "exec" || ssh.Unmarshal(request.Payload, &command) != nil {
					request.Reply(false, nil)
					return
				}
				request.Reply(true, nil)
				body, err := io.ReadAll(channel)
				if err != nil {
					return
				}
				calls <- invocation{command.Command, body}
				if strings.HasSuffix(command.Command, "--status") {
					io.WriteString(channel, volume.Load().(string)+"\n")
				}
				channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			}()
		}
	}()
	address, port, _ := net.SplitHostPort(listener.Addr().String())
	portNumber, _ := strconv.Atoi(port)
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	require.NoError(t, err)
	for _, test := range []struct {
		volume, unlock string
		noLocalKeys    bool
	}{
		{volume: "locked", unlock: "/usr/local/bin/workspace-unlock --initialize"},
		{volume: "unlocked"},
		{volume: "locked", noLocalKeys: true, unlock: "/usr/local/bin/workspace-unlock --initialize"},
	} {
		t.Run(test.volume+fmt.Sprint(test.noLocalKeys), func(t *testing.T) {
			t.Setenv(envConfigPath, filepath.Join(t.TempDir(), "config.json"))
			volume.Store(test.volume)
			owner := ed25519PublicKeyString(seed)
			keys := &resourceKeys{mode: "tmk", signer: signer, storageKey: bytes.Repeat([]byte{0, 1, 2, 10}, 8)}
			if test.noLocalKeys {
				keys = &resourceKeys{service: testService(), mode: "umk", signer: signer}
				keys.umkPath, err = umkRecordPath(accountScope{ControlplaneURL: "https://cp.example", UserID: "user_owner"}, "11111111-1111-4111-8111-111111111111")
				require.NoError(t, err)
			}
			instance, volumeID := "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"
			s := &sandboxSession{box: containerView{Name: "work", Domain: "sandbox.invalid", OwnerPublicKey: owner}, keys: keys, noMonitor: true, expires: time.Now().Add(time.Hour),
				binding: mkBinding{Account: "personal", ContainerID: "11111111-1111-4111-8111-111111111111", InstanceID: &instance, VolumeID: &volumeID},
				profile: ConnectionInfo{HostName: address, Port: portNumber, HostKey: host.PublicKey()}}
			err := s.enroll(t.Context())
			require.NoError(t, err)
			status := <-calls
			require.Equal(t, "/usr/local/bin/workspace-unlock --status", status.command)
			require.Empty(t, status.body)
			if test.unlock == "" {
				require.Empty(t, calls)
				return
			}
			unlock := <-calls
			require.Equal(t, test.unlock, unlock.command)
			require.Equal(t, []byte(keys.storageKey), unlock.body, "only the raw volume key goes to workspace-unlock")
			require.Empty(t, calls)
		})
	}
}

func TestUnlockRequiresUnexpiredAttestationBeforeDial(t *testing.T) {
	for _, expiry := range []time.Time{{}, time.Now().Add(-time.Second)} {
		for _, noMonitor := range []bool{false, true} {
			session := sandboxSession{expires: expiry, noMonitor: noMonitor, keys: &resourceKeys{}, profile: ConnectionInfo{HostKey: testHostKey(t)}}
			require.ErrorContains(t, session.enroll(t.Context()), "attestation expired")
		}
	}
}

func TestMonitorRestartRelinksOnlyAuthorizedSandboxes(t *testing.T) {
	keys := &keyStateServer{}
	const monitorID = "99999999-9999-4999-8999-999999999999"
	type fixture struct {
		name, id, instance, volume string
		key                        mkResource
		host                       ssh.Signer
		owner                      *fakeSandboxOwner
		status                     sandboxStatus
		monitor                    string
	}
	monitorSigner := testSigner(t)
	newHost, oldHost := monitorSigner.PublicKey(), authorizedLine(testSigner(t))
	routes := map[string]string{}
	fixtures := map[string]*fixture{}
	var rows []containerView
	for i, name := range []string{"a", "b", "removed", "nokeys", "unbound", "wrongbinding", "rebooted", "elsewhere"} {
		f := &fixture{name: name, id: fmt.Sprintf("1111111%d-1111-4111-8111-111111111111", i), instance: fmt.Sprintf("2222222%d-2222-4222-8222-222222222222", i),
			volume: fmt.Sprintf("3333333%d-3333-4333-8333-333333333333", i), key: newResourceKey("sandbox"), host: testSigner(t), monitor: monitorID}
		agent := monitorIdentity(f.key.MonitorIdentitySeed)
		f.status = sandboxStatus{Protocol: sandboxOwnerProtocol, InstanceID: f.instance, Volume: "unlocked", MonitorIdentity: &agent, MonitorHostKey: &oldHost}
		if name == "rebooted" {
			f.status.MonitorIdentity = nil
		}
		if name == "elsewhere" {
			f.monitor = "88888888-8888-4888-8888-888888888888"
		}
		f.owner = &fakeSandboxOwner{owner: ed25519.NewKeyFromSeed(f.key.OwnerSeed).Public().(ed25519.PublicKey), reply: func(r ownerCall) any {
			if r.Path == "/enroll" {
				body := r.Body
				var in struct {
					MonitorHostKey string `json:"monitor_host_key"`
				}
				if err := json.Unmarshal(body, &in); err != nil {
					t.Error(err)
					return nil
				}
				f.status.MonitorHostKey = &in.MonitorHostKey
			}
			return f.status
		}}
		routes[net.JoinHostPort(routeName(f.host.PublicKey()), strconv.Itoa(defaultSSHPort))] = testSandboxSSH(t, f.host, f.owner)
		config := fmt.Sprintf("containers: [{env: [{SANDBOX_OWNER_PUBLIC_KEY: %q}, {SANDBOX_INSTANCE_ID: %q}]}]", f.key.OwnerPublicKey, f.instance)
		rows = append(rows, containerView{ID: f.id, Name: name, Repo: DefaultSandboxRepo, Status: statusRunning, ClerkUserID: "user_owner", Config: config,
			Domain: name + ".example", ConfigName: "/tinfoil/containers/" + storageHash([]byte(config)),
			OwnerKeyMode: "tmk", OwnerPublicKey: f.key.OwnerPublicKey, Volumes: map[string]string{"workspace": f.volume},
			NetworkPolicy: &containerNetworkPolicy{EgressMode: "restricted", Egress: []containerPeer{{ContainerID: f.monitor, Port: 22, Alias: &containerAlias{IP: "10.254.0.1", Port: 22}}}}})
		fixtures[f.instance] = f
		fixtures[name] = f
	}
	var changedCreator atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/containers":
			json.NewEncoder(w).Encode(rows)
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/containers/"):
			for _, row := range rows {
				if r.URL.Path == "/api/containers/"+row.ID {
					if changedCreator.Load() && row.Name == "a" {
						row.ClerkUserID = "user_changed"
					}
					json.NewEncoder(w).Encode(row)
					return
				}
			}
			http.NotFound(w, r)
		default:
			keys.ServeHTTP(w, r)
		}
	}))
	defer server.Close()
	cp, scope, _ := testLogin(t, server, keys)
	t.Setenv("HOME", t.TempDir())
	mk, err := newMKSession(cp, scope)
	require.NoError(t, err)
	_, err = mk.update(t.Context(), func(p *mkPayload) error {
		for _, name := range []string{"a", "b", "removed", "unbound", "wrongbinding", "rebooted", "elsewhere"} {
			f := fixtures[name]
			key := f.key
			if name != "unbound" {
				volume := f.volume
				if name == "wrongbinding" {
					volume = "44444444-4444-4444-8444-444444444444"
				}
				key.Binding = &mkBinding{Account: "personal", ContainerID: f.id, InstanceID: &f.instance, VolumeID: &volume}
			}
			if err := addKey(p, key); err != nil {
				return err
			}
		}
		return nil
	})
	require.NoError(t, err)
	revision := keys.revision

	verifier := relayVerifier(func(source string, doc, _ []byte) (connection.Evidence, error) {
		for _, f := range fixtures {
			if strings.Contains(string(doc), f.instance) && strings.Contains(source, storageHash(doc)) {
				return hostEvidence{host: f.host.PublicKey(), expires: time.Now().Add(time.Hour)}, nil
			}
		}
		return nil, errors.New("unknown evidence")
	})

	relayed := map[string]int{}
	var monitorCalls []string
	m := &monitorSession{dir: t.TempDir(), domain: "monitor.example", hostKey: newHost, keys: &resourceKeys{}}
	device, err := ensureSSHIdentity(filepath.Join(m.dir, MonitorDeviceKeyName), nil)
	require.NoError(t, err)
	m.address = testSandboxRoutes(t, monitorSigner, device.PublicKey(), routes)
	m.view.Config.Identities = map[string]struct {
		Key string `json:"key"`
	}{}
	for _, name := range []string{"a", "b", "nokeys", "unbound", "wrongbinding", "rebooted", "elsewhere"} {
		m.view.Config.Identities["sandbox-"+name] = struct {
			Key string `json:"key"`
		}{monitorIdentity(fixtures[name].key.MonitorIdentitySeed)}
	}
	m.request = func(method, path string, input, out any) error {
		raw, _ := json.Marshal(input)
		if path != "/sandboxes/relay" {
			monitorCalls = append(monitorCalls, method+" "+path)
			return errors.New("re-linking must only use the relay")
		}
		require.NotContains(t, string(raw), "monitor_host_key", "Monitor sees only sealed owner requests")
		var in struct {
			InstanceID string `json:"instance_id"`
			Nonce      string `json:"nonce"`
		}
		require.NoError(t, json.Unmarshal(raw, &in))
		f := fixtures[in.InstanceID]
		relayed[f.name]++
		if in.Nonce != "" {
			config := rows[slices.IndexFunc(rows, func(r containerView) bool { return r.ID == f.id })].Config
			return json.Unmarshal(fmt.Appendf(nil, `{"status":200,"headers":{},"body":%q}`, base64.RawURLEncoding.EncodeToString([]byte(config))), out)
		}
		return errors.New("only attestation uses the HTTP relay")
	}

	connections := map[string]*ConnectionInfo{}
	relink := func(id string) error {
		var row containerView
		_, err := cp.Do(t.Context(), "GET", "/api/containers/"+id, nil, nil, nil, &row)
		if err != nil {
			return err
		}
		f := fixtures[row.Name]
		target := &Workload{Container: row, Source: row.ConfigName, Environment: map[string]string{SandboxOwnerEnv: f.key.OwnerPublicKey, "SANDBOX_INSTANCE_ID": f.instance}}
		info, err := cp.service.RelinkSandbox(t.Context(), scope, cp.Client, m, monitorID, id, target, verifier)
		if info != nil {
			connections[row.Name] = info
		}
		return err
	}
	relinkAll := func() []error {
		var failures []error
		for _, row := range rows {
			if err := relink(row.ID); err != nil && !errors.As(err, new(NoLocalKeys)) {
				failures = append(failures, fmt.Errorf("sandbox %s: %w", row.Name, err))
			}
		}
		return failures
	}
	failures := relinkAll()
	var reported []string
	for _, failure := range failures {
		reported = append(reported, failure.Error())
	}
	require.Len(t, failures, 3, "%v", reported)
	all := strings.Join(reported, "\n")
	require.Contains(t, all, "sandbox wrongbinding:")
	require.Contains(t, all, "no longer matches")
	require.Contains(t, all, "sandbox rebooted: its saved Monitor identity is not active")
	require.Contains(t, all, "sandbox elsewhere: its inventory changed")
	host := authorizedKeyLine(newHost)
	for _, name := range []string{"a", "b"} {
		f := fixtures[name]
		f.owner.mu.Lock()
		require.Equal(t, host, *f.status.MonitorHostKey, name)
		f.owner.mu.Unlock()
		var paths []string
		for _, request := range f.owner.calls() {
			paths = append(paths, request.Method+" "+request.Path)
		}
		require.Equal(t, []string{"GET /status", "POST /enroll"}, paths, name)
	}
	require.Equal(t, []string{"GET /status"}, []string{fixtures["rebooted"].owner.calls()[0].Method + " " + fixtures["rebooted"].owner.calls()[0].Path})
	require.Len(t, fixtures["rebooted"].owner.calls(), 1, "a rebooted sandbox is not enrolled or unlocked here")
	for _, name := range []string{"removed", "nokeys", "unbound", "wrongbinding", "elsewhere"} {
		require.Zero(t, relayed[name], "%s is not contacted", name)
	}
	require.Empty(t, monitorCalls, "no Monitor enrollment, unlock or restore")
	require.Equal(t, revision, keys.revision, "re-linking never writes the key bundle")

	require.Len(t, connections, 2)
	require.Equal(t, newHost.Marshal(), connections["a"].Jump.HostKey.Marshal())
	require.Equal(t, "monitor.example", connections["a"].Jump.HostKeyAlias)
	require.Equal(t, "a.monitor", connections["a"].Jump.Name)
	require.Equal(t, routeName(fixtures["a"].host.PublicKey()), connections["a"].HostName)

	// A second open finds every pin current and changes nothing.
	for _, name := range []string{"a", "b"} {
		fixtures[name].owner.reset()
	}
	require.Len(t, relinkAll(), 3)
	for _, name := range []string{"a", "b"} {
		require.Len(t, fixtures[name].owner.calls(), 1, "%s: status only", name)
	}

	for _, tc := range []struct {
		name, mode, want string
		changedCreator   bool
	}{
		{name: "changed creator in fresh detail", mode: "tmk", changedCreator: true, want: "inventory changed"},
		{name: "unsupported custody pairing", mode: "umk", want: "a UMK Monitor cannot serve the synced sandbox"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changedCreator.Store(tc.changedCreator)
			m.keys.mode = tc.mode
			before := relayed["a"]
			err := relink(fixtures["a"].id)
			require.ErrorContains(t, err, tc.want)
			require.Equal(t, before, relayed["a"], "invalid ownership or custody must not contact the sandbox")
			require.Equal(t, revision, keys.revision, "re-linking does not change key state")
		})
	}
}
