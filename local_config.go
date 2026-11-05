package main

import (
	"fmt"

	"github.com/tinfoilsh/tinfoil-cli/internal/connection"
)

var localConfigBytes []byte

func readLocalConfig() ([]byte, error) {
	if localConfigFile == "" {
		return nil, fmt.Errorf("this container requires --config with its trusted local config file")
	}
	// Descriptor checks and verification must use the same exact file bytes.
	if localConfigBytes != nil {
		return localConfigBytes, nil
	}
	config, err := connection.ReadConfig(localConfigFile)
	if err != nil {
		return nil, err
	}
	localConfigBytes = config.Bytes()
	return localConfigBytes, nil
}

func checkLocalConfigDigest(expected string) error {
	data, err := readLocalConfig()
	if err != nil {
		return err
	}
	config, err := connection.NewConfig(data)
	if err != nil {
		return err
	}
	return config.CheckDigest(expected)
}
