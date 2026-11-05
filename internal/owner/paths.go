package owner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var resourceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$`)
var resourceIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Monitor names are scoped to an account and control plane.
type Scope struct {
	ControlplaneURL string `json:"controlplane_url"`
	OrgID           string `json:"org_id,omitempty"`
	UserID          string `json:"user_id"`
	OrgName         string `json:"-"` // Display only; account identity must survive renames.
	UserName        string `json:"-"`
}

func (s Scope) Account() string {
	if s.OrgID != "" {
		return s.OrgID
	}
	return "personal"
}

func hash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Names make new directories readable; UUIDs identify existing credentials even
// after a resource is renamed. Keep saved paths stable for installed SSH profiles.
func resourceDirectory(configPath string, scope Scope, id, name string) (string, error) {
	if !resourceIDPattern.MatchString(id) {
		return "", errors.New("invalid resource UUID")
	}
	accountDir, err := accountDir(configPath, scope)
	if err != nil {
		return "", err
	}
	dir, err := existingCredentialDir(accountDir, id)
	if err != nil || dir != "" {
		return dir, err
	}
	name = strings.TrimSpace(name)
	if !resourceNamePattern.MatchString(name) {
		// Readable labels are optional, including on the first connection.
		return filepath.Join(accountDir, id), nil
	}
	return filepath.Join(accountDir, name+"-"+id), nil
}

func accountDir(configPath string, scope Scope) (string, error) {
	data, _ := json.Marshal(scope)
	root, accountID := filepath.Join(filepath.Dir(configPath), "resources"), hash(data)
	dir, err := existingCredentialDir(root, accountID)
	if err != nil || dir != "" {
		return dir, err
	}
	return filepath.Join(root, accountDirectoryLabel(scope)+"-"+accountID), nil
}

func accountDirectoryLabel(scope Scope) string {
	name := strings.TrimSpace(scope.UserName)
	if name == "" {
		name = scope.UserID
	}
	account := "user-" + name
	if scope.OrgID != "" {
		name := strings.TrimSpace(scope.OrgName)
		if name == "" {
			name = scope.OrgID
		}
		account = "org-" + name
	}
	// Keep paths portable and bounded even when organization names contain
	// separators or Unicode. The full scope hash retains their exact identity.
	parts := strings.FieldsFunc(strings.ToLower(account), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_')
	})
	label := strings.Join(parts, "-")
	if len(label) > 120 {
		label = label[:120]
	}
	return strings.Trim(label, ".-_")
}

func umkPath(configPath string, scope Scope, containerID string) (string, error) {
	dir, err := accountDir(configPath, scope)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "umk-"+hash([]byte(containerID))[:32]+".json"), nil
}

// Resolve both readable directories and the deployed identifier-only layout.
// A changed display name must not move credentials referenced by SSH profiles.
func existingCredentialDir(parent, id string) (string, error) {
	entries, err := os.ReadDir(parent)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	var saved string
	for _, entry := range entries {
		if entry.Name() != id && !strings.HasSuffix(entry.Name(), "-"+id) {
			continue
		}
		path := filepath.Join(parent, entry.Name())
		if !entry.IsDir() {
			return "", fmt.Errorf("credential path %s must be a directory", path)
		}
		if saved != "" {
			return "", fmt.Errorf("multiple credential directories for %s: %s and %s; restore a single original credential directory", id, saved, path)
		}
		saved = path
	}
	return saved, nil
}
