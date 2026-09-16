package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

type volumeView struct {
	Name           string   `json:"name"`
	HostName       string   `json:"host_name"`
	SizeBytes      int64    `json:"size_bytes"`
	AllocatedBytes int64    `json:"allocated_bytes,omitempty"`
	UsedBy         []string `json:"used_by"`
	CreatedAt      string   `json:"created_at"`
}

const (
	bytesPerMiB = 1 << 20
	bytesPerGiB = 1 << 30
)

var volumeNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

var (
	volumeCreateSize string
	volumeCreateHost string
	volumeYes        bool
)

func init() {
	rootCmd.AddCommand(volumeCmd)
	volumeCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")
	volumeCmd.AddCommand(volumeListCmd, volumeCreateCmd, volumeDeleteCmd)

	volumeCreateCmd.Flags().StringVar(&volumeCreateSize, "size", "", "Volume size, e.g. 100GiB [required]")
	volumeCreateCmd.Flags().StringVar(&volumeCreateHost, "host", "", "Host to create the volume on (see 'tinfoil container hosts')")
	_ = volumeCreateCmd.MarkFlagRequired("size")
	volumeDeleteCmd.Flags().BoolVar(&volumeYes, "yes", false, "Skip the confirmation prompt")
	silenceUsageRecursive(volumeCmd)
}

var volumeCmd = &cobra.Command{
	Use:     "volume",
	Aliases: []string{"volumes"},
	Short:   "Manage persistent volumes for containers",
}

var volumeListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List volumes in the current organization",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		var list []volumeView
		if _, err := client.do("GET", "/api/volumes", nil, nil, &list); err != nil {
			return err
		}
		return renderVolumes(list)
	},
}

var volumeCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a volume",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, err := volumeName(args[0])
		if err != nil {
			return err
		}
		body := map[string]any{"name": name, "size": volumeCreateSize}
		if volumeCreateHost != "" {
			body["host_name"] = volumeCreateHost
		}
		client, err := authedClient()
		if err != nil {
			return err
		}
		var created volumeView
		if _, err := client.do("POST", "/api/volumes", nil, body, &created); err != nil {
			return err
		}
		if outputFormat == "json" {
			return printJSON(created)
		}
		return renderVolumes([]volumeView{created})
	},
}

var volumeDeleteCmd = &cobra.Command{
	Use:     "delete [name]",
	Aliases: []string{"rm", "destroy"},
	Short:   "Delete a volume and erase its data (fails while attached)",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, err := volumeName(args[0])
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Deleting %s erases everything stored on it.\n\n", name)
		if err := confirmYes(volumeYes, "deleting a volume"); err != nil {
			return err
		}
		client, err := authedClient()
		if err != nil {
			return err
		}
		if _, err := client.do("DELETE", pathf("/api/volumes/%s", name), nil, nil, nil); err != nil {
			return err
		}
		fmt.Printf("Deleted volume %s\n", name)
		return nil
	},
}

func volumeName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if !volumeNamePattern.MatchString(name) {
		return "", fmt.Errorf("invalid volume name %q: use lowercase letters, digits or dashes, starting with a letter, up to 63 characters", raw)
	}
	return name, nil
}

func formatBytes(n int64) string {
	unit, div := "GiB", float64(bytesPerGiB)
	if n < bytesPerGiB {
		unit, div = "MiB", float64(bytesPerMiB)
	}
	return strings.TrimSuffix(fmt.Sprintf("%.1f", float64(n)/div), ".0") + unit
}

func renderVolumes(list []volumeView) error {
	if outputFormat == "json" {
		return printJSON(list)
	}
	if len(list) == 0 {
		fmt.Println("No volumes.")
		return nil
	}
	fmt.Printf("%-32s  %-10s  %-24s  %-30s  %s\n", "NAME", "SIZE", "HOST", "USED BY", "CREATED")
	for _, v := range list {
		used := strings.Join(v.UsedBy, ", ")
		if used == "" {
			used = "-"
		}
		fmt.Printf("%-32s  %-10s  %-24s  %-30s  %s\n",
			truncate(v.Name, 32), formatBytes(v.SizeBytes), truncate(v.HostName, 24), truncate(used, 30), v.CreatedAt,
		)
	}
	return nil
}
