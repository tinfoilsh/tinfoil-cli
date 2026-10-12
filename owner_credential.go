package main

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"gopkg.in/yaml.v3"
)

const ownerPHCPrefix = "$argon2id$v=19$m=262144,t=3,p=4$"
const maxSuppliedOwnerBytes = 4096

// Legacy key files stay untouched. New records retain the salt and distinguish
// supplied UTF-8 credentials from generated or imported legacy random keys.
type ownerCredential struct {
	Version   int    `json:"version"`
	Key       []byte `json:"key"`
	Argon2ID  string `json:"argon2id"`
	LegacyKey bool   `json:"legacy_key,omitempty"`
}

func ownerPHC(key, salt []byte) string {
	hash := argon2.IDKey(key, salt, 3, 262144, 4, 32)
	defer clear(hash)
	return ownerPHCPrefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
}

func ownerPHCSalt(phc string) ([]byte, error) {
	fields := strings.Split(strings.TrimPrefix(phc, ownerPHCPrefix), "$")
	if !strings.HasPrefix(phc, ownerPHCPrefix) || len(fields) != 2 {
		return nil, errors.New("unsupported owner Argon2id commitment")
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(fields[0])
	hash, hashErr := base64.RawStdEncoding.Strict().DecodeString(fields[1])
	if err != nil || hashErr != nil || len(salt) != 32 || len(hash) != 32 || base64.RawStdEncoding.EncodeToString(salt) != fields[0] || base64.RawStdEncoding.EncodeToString(hash) != fields[1] {
		return nil, errors.New("invalid owner Argon2id commitment")
	}
	return salt, nil
}

func newOwnerCredential(key []byte, legacy bool) (*ownerCredential, error) {
	if len(key) < 16 || len(key) > maxSuppliedOwnerBytes {
		return nil, errors.New("owner credential must contain 16 to 4096 bytes")
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return &ownerCredential{Version: 1, Key: bytes.Clone(key), Argon2ID: ownerPHC(key, salt), LegacyKey: legacy}, nil
}

func suppliedOwnerCredential(path string, legacySize int, stdin io.Reader) (*ownerCredential, error) {
	var reader io.Reader = stdin
	if path != "-" {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		reader = file
	}
	raw, err := io.ReadAll(io.LimitReader(reader, maxSuppliedOwnerBytes*2+1024))
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	// Saved records can be passed back to the CLI without losing their salt.
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		var record map[string]json.RawMessage
		if json.Unmarshal(raw, &record) == nil && record["version"] != nil && record["key"] != nil {
			credential, err := decodeOwnerCredential(raw, legacySize)
			if err != nil {
				return nil, err
			}
			if _, err := credential.commitment(credential.Argon2ID); err != nil {
				return nil, err
			}
			return credential, nil
		}
	}
	encoded := strings.TrimSpace(string(raw))
	if decoded, err := base64.StdEncoding.Strict().DecodeString(encoded); err == nil && len(decoded) == legacySize && base64.StdEncoding.EncodeToString(decoded) == encoded {
		defer clear(decoded)
		return newOwnerCredential(decoded, true)
	}
	if !utf8.Valid(raw) {
		return nil, errors.New("supplied owner credential must be UTF-8 text or an existing canonical encoded key")
	}
	return newOwnerCredential(raw, false)
}

func readOwnerCredential(path string, legacySize int) (*ownerCredential, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	return decodeOwnerCredential(raw, legacySize)
}

func decodeOwnerCredential(raw []byte, legacySize int) (*ownerCredential, error) {
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		var credential ownerCredential
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&credential); err != nil {
			return nil, errors.New("invalid credential file")
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			return nil, errors.New("invalid credential file")
		}
		if credential.Version != 1 || len(credential.Key) < 16 || len(credential.Key) > maxSuppliedOwnerBytes || (credential.LegacyKey && len(credential.Key) != legacySize) || (!credential.LegacyKey && !utf8.Valid(credential.Key)) {
			return nil, errors.New("invalid credential file")
		}
		if _, err := ownerPHCSalt(credential.Argon2ID); err != nil {
			return nil, fmt.Errorf("invalid credential file: %w", err)
		}
		return &credential, nil
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != legacySize {
		return nil, errors.New("invalid legacy credential; restore the saved key instead of replacing it")
	}
	return &ownerCredential{Key: key, LegacyKey: true}, nil
}

func saveOwnerCredential(path string, credential *ownerCredential, legacySize int) error {
	old, err := readOwnerCredential(path, legacySize)
	if err == nil {
		defer clear(old.Key)
		if !bytes.Equal(old.Key, credential.Key) {
			return fmt.Errorf("%s already holds a different key; restore the original credential", path)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.MarshalIndent(credential, "", "  ")
	if err != nil {
		return err
	}
	defer clear(data)
	return writeNewFile(path, data)
}

func (c *ownerCredential) commitment(existing string) (string, error) {
	if strings.HasPrefix(existing, "$argon2") {
		salt, err := ownerPHCSalt(existing)
		if err != nil {
			return "", err
		}
		actual := ownerPHC(c.Key, salt)
		if subtle.ConstantTimeCompare([]byte(actual), []byte(existing)) != 1 {
			return "", errors.New("supplied credential does not match the saved owner binding")
		}
		return existing, nil
	}
	if existing != "" {
		if !c.LegacyKey || subtle.ConstantTimeCompare([]byte(storageHash(c.Key)), []byte(existing)) != 1 {
			return "", errors.New("supplied credential does not match the saved legacy owner binding")
		}
		return existing, nil
	}
	if c.Argon2ID == "" {
		created, err := newOwnerCredential(c.Key, c.LegacyKey)
		if err != nil {
			return "", err
		}
		c.Argon2ID = created.Argon2ID
		clear(created.Key)
	}
	return c.commitment(c.Argon2ID)
}

// Only the fixed protocol parameters are accepted from an existing measured
// configuration. Both bindings cannot be active at the same time.
func ownerBinding(raw []byte, legacyEnv, argonEnv string) (name, value string, err error) {
	var doc struct {
		Containers []struct {
			Env []any `yaml:"env"`
		} `yaml:"containers"`
	}
	if err = yaml.Unmarshal(raw, &doc); err != nil {
		return
	}
	values := map[string]string{}
	present := map[string]bool{}
	for _, container := range doc.Containers {
		for _, entry := range container.Env {
			switch item := entry.(type) {
			case string:
				k, v, _ := strings.Cut(item, "=")
				if k == legacyEnv || k == argonEnv {
					if present[k] {
						return "", "", errors.New("duplicate owner binding")
					}
					present[k] = true
					values[k] = v
				}
			case map[string]any:
				for k, v := range item {
					if k == legacyEnv || k == argonEnv {
						if present[k] {
							return "", "", errors.New("duplicate owner binding")
						}
						text, ok := v.(string)
						if !ok {
							return "", "", errors.New("invalid owner binding")
						}
						present[k] = true
						values[k] = text
					}
				}
			}
		}
	}
	if values[legacyEnv] != "" && values[argonEnv] != "" {
		return "", "", errors.New("both legacy and Argon2id owner bindings are set")
	}
	if present[argonEnv] && (values[argonEnv] != "" || values[legacyEnv] == "") {
		return argonEnv, values[argonEnv], nil
	}
	if present[legacyEnv] {
		return legacyEnv, values[legacyEnv], nil
	}
	return "", "", errors.New("template has no owner binding")
}

func ownerEnvName(commitment, legacyEnv, argonEnv string) string {
	if strings.HasPrefix(commitment, ownerPHCPrefix) {
		return argonEnv
	}
	return legacyEnv
}

func prepareOwnerCredential(path, inputPath string, legacySize int, existingConfig, template []byte, legacyEnv, argonEnv string) (*ownerCredential, string, error) {
	credential, err := readOwnerCredential(path, legacySize)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}
	if inputPath != "" {
		supplied, readErr := suppliedOwnerCredential(inputPath, legacySize, os.Stdin)
		if readErr != nil {
			return nil, "", readErr
		}
		if credential != nil {
			equal := bytes.Equal(credential.Key, supplied.Key)
			clear(supplied.Key)
			if !equal {
				return nil, "", fmt.Errorf("%s already holds a different key; the saved credential was not replaced", path)
			}
		} else {
			credential = supplied
		}
	}
	if credential == nil {
		if existingConfig != nil {
			return nil, "", errors.New("existing resource has no local owner credential; restore its backup or supply its original key file")
		}
		raw := make([]byte, legacySize)
		if _, err := rand.Read(raw); err != nil {
			return nil, "", err
		}
		defer clear(raw)
		credential, err = newOwnerCredential(raw, true)
		if err != nil {
			return nil, "", err
		}
	}
	raw := template
	if existingConfig != nil {
		raw = existingConfig
	}
	name, expected, err := ownerBinding(raw, legacyEnv, argonEnv)
	if err != nil {
		return nil, "", err
	}
	var commitment string
	if existingConfig != nil {
		if expected == "" {
			return nil, "", errors.New("existing resource has no measured owner commitment")
		}
		commitment, err = credential.commitment(expected)
	} else if name == legacyEnv {
		if !credential.LegacyKey || len(credential.Key) != legacySize {
			return nil, "", errors.New("this release does not support passphrases; select the current approved release")
		}
		commitment = storageHash(credential.Key)
	} else {
		commitment, err = credential.commitment("")
	}
	if err != nil {
		return nil, "", err
	}
	if strings.HasPrefix(commitment, ownerPHCPrefix) {
		credential.Argon2ID = commitment
	}
	return credential, commitment, nil
}
