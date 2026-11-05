package controlplane

import (
	"encoding/json"
	"fmt"
	"strings"
)

type NetworkPolicy struct {
	Public     bool   `json:"public"`
	EgressMode string `json:"egress_mode"`
	Egress     []Peer `json:"egress"`
}

type Peer struct {
	ContainerID string `json:"container_id"`
	Port        int    `json:"port"`
	Alias       *Alias `json:"alias,omitempty"`
}

type Alias struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// Container mirrors the controlplane's containerResponse. We only model
// the fields the CLI actually displays or forwards; everything else stays in
// RawMessage form so updates to the API don't break decoding here.
type Container struct {
	Config        string         `json:"config"`
	NetworkPolicy *NetworkPolicy `json:"network_policy"`

	ID                   string           `json:"id"`
	Name                 string           `json:"name"`
	Repo                 string           `json:"repo"`
	Source               string           `json:"source,omitempty"`
	ConfigName           string           `json:"config_name,omitempty"`
	ProjectID            string           `json:"project_id"`
	ClerkUserID          string           `json:"clerk_user_id,omitempty"`
	Status               string           `json:"status"`
	CurrentTag           string           `json:"current_tag"`
	Domain               string           `json:"domain"`
	InternalDomain       string           `json:"internal_domain"`
	HostName             string           `json:"host_name"`
	HostGpuType          string           `json:"host_gpu_type"`
	HostCpuType          string           `json:"host_cpu_type"`
	CPUs                 int              `json:"cpus"`
	GPUs                 int              `json:"gpus"`
	MemoryMB             int              `json:"memory_mb"`
	Variables            json.RawMessage  `json:"variables"`
	Secrets              []string         `json:"secrets"`
	SSHKeys              []string         `json:"ssh_keys"`
	Debug                bool             `json:"debug"`
	Held                 bool             `json:"held"`
	MarkLatestRelease    *bool            `json:"mark_latest_release,omitempty"`
	DisableCCMode        bool             `json:"disable_cc_mode"`
	GithubAppConnected   bool             `json:"github_app_connected"`
	DisplayOrder         int32            `json:"display_order"`
	UpdateTag            string           `json:"update_tag"`
	UpdateStatus         string           `json:"update_status"`
	UpdateType           string           `json:"update_type"`
	UpdateStrategy       string           `json:"update_strategy"`
	UpdateConfig         *CandidateConfig `json:"update_config,omitempty"`
	TinfoildDeploymentID string           `json:"tinfoild_deployment_id,omitempty"`
	UpdateDeploymentID   string           `json:"update_deployment_id,omitempty"`
	BootStages           BootStages       `json:"boot_stages"`
	UpdateBootStages     BootStages       `json:"update_boot_stages"`
	ErrorMessage         string           `json:"error_message"`
	CreatedAt            string           `json:"created_at"`
	UpdatedAt            string           `json:"updated_at"`
	SSHPort              int              `json:"ssh_port"`
	HostID               string           `json:"host_id,omitempty"`

	LastDeployAttemptError string `json:"last_deploy_attempt_error,omitempty"`

	Connections *Connections `json:"connections,omitempty"`
	// VolumeSlots are the volumes tinfoil-config.yml declares; Volumes maps a
	// slot to the attached volume ID. Only the single-container view has them.
	VolumeSlots []VolumeSlot      `json:"volume_slots,omitempty"`
	Volumes     map[string]string `json:"volumes,omitempty"`

	OwnerKeyMode   string `json:"owner_key_mode,omitempty"`
	OwnerPublicKey string `json:"owner_public_key,omitempty"`
}

type CandidateConfig struct {
	Hold *bool `json:"hold,omitempty"`
}

func (c Container) CandidateHeld() bool {
	if c.UpdateConfig != nil && c.UpdateConfig.Hold != nil {
		return *c.UpdateConfig.Hold
	}
	return c.Held
}

// BootStage mirrors one entry of the boot progress tinfoild reports while a
// deployment comes up. Stages nest.
type BootStage struct {
	Name   string      `json:"name"`
	Status string      `json:"status"`
	Detail string      `json:"detail,omitempty"`
	Stages []BootStage `json:"stages,omitempty"`
}

type BootStages []BootStage

func (stages *BootStages) UnmarshalJSON(raw []byte) error {
	if strings.HasPrefix(strings.TrimSpace(string(raw)), `"`) {
		var decoded []byte
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return fmt.Errorf("decoding boot stages: %w", err)
		}
		raw = decoded
	}
	return json.Unmarshal(raw, (*[]BootStage)(stages))
}

type ConnectionDescriptor struct {
	URL          string `json:"url"`
	Repo         string `json:"repo"`
	Tag          string `json:"tag"`
	ConfigName   string `json:"config_name,omitempty"`
	ConfigDigest string `json:"config_digest,omitempty"`
}

type Connections struct {
	Production *ConnectionDescriptor `json:"production"`
	Review     *ConnectionDescriptor `json:"review"`
}

// VolumeSlot is a volume declared in tinfoil-config.yml. A key secret marks
// the slot as required at deploy.
type VolumeSlot struct {
	Name      string `json:"name"`
	KeySecret string `json:"key_secret,omitempty"`
}
