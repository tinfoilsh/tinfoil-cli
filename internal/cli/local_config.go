package cli

import (
	"bytes"
	"encoding/json/v2"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tinfoil-cli/internal/connection"
	tinfoilconfig "github.com/tinfoilsh/tinfoil-config"
	"go.yaml.in/yaml/v3"
	"golang.org/x/term"
)

func newContainerConfigCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "config [file]",
		Short: "Print the JSON config for a config file and its SHA-256 digest",
		Long: "A config that pins cvm-version " + tinfoilconfig.JSONConfigMinVersion + ` or later is stored and measured as JSON.
The JSON config goes to standard output and its digest to standard error.`,
		Example: `  Save the JSON config of a YAML config
  tinfoil container config tinfoil-config.yml > tinfoil-config.json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := connection.ReadConfig(args[0])
			if err != nil {
				return err
			}
			translated, ok, err := jsonConfig(config.Bytes())
			if err != nil {
				return fmt.Errorf("invalid config %s: %w", args[0], err)
			}
			if !ok {
				return fmt.Errorf("%s does not pin cvm-version %s or later, so it has no JSON config", args[0], tinfoilconfig.JSONConfigMinVersion)
			}
			streams := commandStreams(cmd)
			if _, err := streams.out.Write(translated); err != nil {
				return err
			}
			// Redirected output is the config's exact bytes; a terminal gets a line break.
			if term.IsTerminal(streamFD(streams.out)) {
				fmt.Fprintln(streams.out)
			}
			fmt.Fprintf(streams.err, "sha256:%s\n", storageHash(translated))
			return nil
		},
	}
}

func readLocalConfig(rootOpts *rootOptions) ([]byte, error) {
	if rootOpts.localConfigFile == "" {
		return nil, fmt.Errorf("this container requires --config with its trusted local config file")
	}
	// Descriptor checks and verification must use the same exact file bytes.
	if rootOpts.localConfigBytes != nil {
		return rootOpts.localConfigBytes, nil
	}
	config, err := connection.ReadConfig(rootOpts.localConfigFile)
	if err != nil {
		return nil, err
	}
	data := config.Bytes()
	// Tinfoil stores and measures the JSON config, so that is what gets sent,
	// compared and embedded.
	if translated, ok, err := jsonConfig(data); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", rootOpts.localConfigFile, err)
	} else if ok && !bytes.Equal(translated, data) {
		if rootOpts.notices != nil {
			fmt.Fprintf(rootOpts.notices(), "Translated %s to its JSON config, sha256:%s\n", rootOpts.localConfigFile, storageHash(translated))
		}
		data = translated
	}
	rootOpts.localConfigBytes = data
	return rootOpts.localConfigBytes, nil
}

func checkLocalConfigDigest(rootOpts *rootOptions, expected string) error {
	data, err := readLocalConfig(rootOpts)
	if err != nil {
		return err
	}
	config, err := connection.NewConfig(data)
	if err != nil {
		return err
	}
	return config.CheckDigest(expected)
}

// jsonConfig returns the JSON config for data, the bytes Tinfoil stores and
// measures, when data pins a cvm-version that takes one. It reports false for
// any other config, which stays the YAML it is and is not read further here.
func jsonConfig(data []byte) ([]byte, bool, error) {
	if !isJSONConfig(data) {
		var pin struct {
			Version string `yaml:"cvm-version"`
		}
		if yaml.Unmarshal(data, &pin) != nil || !tinfoilconfig.RequiresJSON(pin.Version) {
			return nil, false, nil
		}
	}
	translated, err := tinfoilconfig.Normalize(data, tinfoilconfig.Options{})
	if err != nil {
		return nil, false, err
	}
	return translated, isJSONConfig(translated), nil
}

// isJSONConfig reports whether data is a JSON object that pins a cvm-version
// whose config is JSON.
func isJSONConfig(data []byte) bool {
	var pin struct {
		Version *string `json:"cvm-version"`
	}
	return json.Unmarshal(data, &pin) == nil && pin.Version != nil && tinfoilconfig.RequiresJSON(*pin.Version)
}
