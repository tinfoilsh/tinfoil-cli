package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
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
	file, err := os.Open(localConfigFile)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, configendorsement.MaxConfigSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	if len(data) == 0 || len(data) > configendorsement.MaxConfigSize {
		return nil, fmt.Errorf("config must contain between 1 and %d bytes", configendorsement.MaxConfigSize)
	}
	localConfigBytes = data
	return data, nil
}

func checkLocalConfigDigest(expected string) error {
	data, err := readLocalConfig()
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != expected {
		return fmt.Errorf("local config does not match the selected container's config digest")
	}
	return nil
}
