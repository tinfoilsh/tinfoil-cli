package main

import (
	"fmt"

	"github.com/tinfoilsh/tinfoil-cli/internal/connection"
)

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
	rootOpts.localConfigBytes = config.Bytes()
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
