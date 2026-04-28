package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// matches services.RegistryGHCR / RegistryGCR / RegistryDockerHub on the
// controlplane side.
const (
	registryGHCR      = "ghcr"
	registryGCR       = "gcr"
	registryDockerHub = "dockerhub"
)

type registryStatus struct {
	HasCredentials bool   `json:"has_credentials"`
	Username       string `json:"username,omitempty"`
	UpdatedAt      string `json:"updated_at,omitempty"`
	Expired        bool   `json:"expired"`
}

type registryListResponse struct {
	GHCR      registryStatus `json:"ghcr"`
	GCR       registryStatus `json:"gcr"`
	DockerHub registryStatus `json:"dockerhub"`
}

var (
	registryUsername string
	registryToken    string
	registryKeyFile  string
)

func init() {
	rootCmd.AddCommand(registryCmd)
	registryCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")
	registryCmd.AddCommand(registryListCmd, registrySetCmd, registryDeleteCmd)

	registrySetCmd.Flags().StringVar(&registryUsername, "username", "", "Registry username (ghcr, dockerhub)")
	registrySetCmd.Flags().StringVar(&registryToken, "token", "", "Registry token / password (ghcr, dockerhub)")
	registrySetCmd.Flags().StringVar(&registryKeyFile, "key-file", "", "Path to GCP service account JSON (gcr); use - for stdin")
	silenceUsageRecursive(registryCmd)
}

var registryCmd = &cobra.Command{
	Use:          "registry",
	Aliases:      []string{"registries"},
	Short:        "Manage container registry credentials (ghcr, gcr, dockerhub)",
	SilenceUsage: true,
}

var registryListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "Show which registries have credentials configured",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		var resp registryListResponse
		if _, err := client.do("GET", "/api/registry-credentials", nil, nil, &resp); err != nil {
			return err
		}
		if outputFormat == "json" {
			return printJSON(resp)
		}
		fmt.Printf("%-12s  %-10s  %-30s  %s\n", "REGISTRY", "STATUS", "USERNAME", "UPDATED")
		printRegistry := func(name string, s registryStatus) {
			status := "missing"
			if s.HasCredentials {
				status = "ok"
				if s.Expired {
					status = "expired"
				}
			}
			user := s.Username
			if user == "" {
				user = "-"
			}
			updated := s.UpdatedAt
			if updated == "" {
				updated = "-"
			}
			fmt.Printf("%-12s  %-10s  %-30s  %s\n", name, status, user, updated)
		}
		printRegistry(registryGHCR, resp.GHCR)
		printRegistry(registryGCR, resp.GCR)
		printRegistry(registryDockerHub, resp.DockerHub)
		return nil
	},
}

var registrySetCmd = &cobra.Command{
	Use:   "set [ghcr|gcr|dockerhub]",
	Short: "Set credentials for a registry",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		registry := strings.ToLower(args[0])
		body, err := buildRegistryBody(registry, cmd)
		if err != nil {
			return err
		}
		var resp map[string]any
		if _, err := client.do("PUT", pathf("/api/registry-credentials/%s", registry), nil, body, &resp); err != nil {
			return err
		}
		if msg, ok := resp["message"].(string); ok && msg != "" {
			fmt.Println(msg)
			return nil
		}
		fmt.Printf("%s credentials updated\n", registry)
		return nil
	},
}

var registryDeleteCmd = &cobra.Command{
	Use:     "delete [ghcr|gcr|dockerhub]",
	Aliases: []string{"rm", "remove"},
	Short:   "Delete credentials for a registry",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		registry := strings.ToLower(args[0])
		if !validRegistry(registry) {
			return fmt.Errorf("registry must be one of: %s, %s, %s", registryGHCR, registryGCR, registryDockerHub)
		}
		if _, err := client.do("DELETE", pathf("/api/registry-credentials/%s", registry), nil, nil, nil); err != nil {
			return err
		}
		fmt.Printf("Deleted %s credentials\n", registry)
		return nil
	},
}

func validRegistry(name string) bool {
	return name == registryGHCR || name == registryGCR || name == registryDockerHub
}

func buildRegistryBody(registry string, cmd *cobra.Command) (map[string]any, error) {
	switch registry {
	case registryGHCR, registryDockerHub:
		if registryUsername == "" || registryToken == "" {
			return nil, fmt.Errorf("--username and --token are required for %s", registry)
		}
		return map[string]any{"username": registryUsername, "token": registryToken}, nil
	case registryGCR:
		if registryKeyFile == "" {
			return nil, fmt.Errorf("--key-file is required for gcr")
		}
		var (
			data []byte
			err  error
		)
		if registryKeyFile == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(registryKeyFile)
		}
		if err != nil {
			return nil, fmt.Errorf("reading key file: %w", err)
		}
		return map[string]any{"key": strings.TrimSpace(string(data))}, nil
	default:
		return nil, fmt.Errorf("registry must be one of: %s, %s, %s", registryGHCR, registryGCR, registryDockerHub)
	}
}
