package connection

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
)

// Config keeps descriptor checks and verification bound to one immutable snapshot.
type Config struct {
	data []byte
}

func NewConfig(data []byte) (*Config, error) {
	if len(data) == 0 || len(data) > configendorsement.MaxConfigSize {
		return nil, fmt.Errorf("config must contain between 1 and %d bytes", configendorsement.MaxConfigSize)
	}
	return &Config{data: bytes.Clone(data)}, nil
}

func ReadConfig(path string) (*Config, error) {
	if path == "" {
		return nil, fmt.Errorf("this container requires --config with its trusted local config file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, configendorsement.MaxConfigSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	return NewConfig(data)
}

func (c *Config) Bytes() []byte {
	return bytes.Clone(c.data)
}

func (c *Config) CheckDigest(expected string) error {
	digest := sha256.Sum256(c.data)
	if hex.EncodeToString(digest[:]) != expected {
		return fmt.Errorf("local config does not match the selected container's config digest")
	}
	return nil
}
