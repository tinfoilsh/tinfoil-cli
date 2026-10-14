package main

import (
	"errors"
	"fmt"
	"net/http"

	"go.yaml.in/yaml/v3"
)

// Keep the checked configuration and its measured bindings together through
// attestation and credential delivery. Never rebuild the source after approval.
type workloadTarget struct {
	containerView
	source string
	env    map[string]string
}

// The controlplane supplies the config; tinfoil-go verifies its endorsement and
// measured digest before a connection can carry owner credentials.
func resolveWorkload(row containerView, repository, assertion string) (*workloadTarget, error) {
	if localConfigFile != "" {
		return nil, errors.New("managed workloads use their published configuration; pin it with --repo instead of --config")
	}
	if row.Repo != repository || row.Debug || row.Config == "" {
		return nil, errors.New("unexpected workload configuration")
	}
	env, err := measuredEnvironment(row.Config)
	if err != nil {
		return nil, err
	}
	digest := storageHash([]byte(row.Config))
	if row.ConfigName != "/tinfoil/containers/"+digest {
		return nil, errors.New("workload config reference does not match its digest")
	}
	target, err := parseConnectionDescriptor(connectionDescriptor{URL: "https://" + row.Domain, ConfigName: row.ConfigName, ConfigDigest: digest})
	if err != nil {
		return nil, err
	}
	if err := trustConnectionSource(target.source, assertion); err != nil {
		return nil, err
	}
	return &workloadTarget{containerView: row, source: target.source, env: env}, nil
}

func missingContainer(err error) bool {
	var missing *cpError
	return errors.As(err, &missing) && missing.Status == http.StatusNotFound
}

func measuredEnvironment(raw string) (map[string]string, error) {
	var config struct{ Containers []struct{ Env []yaml.Node } }
	if err := yaml.Unmarshal([]byte(raw), &config); err != nil {
		return nil, err
	}
	values := map[string]string{}
	seen := map[string]bool{}
	for _, container := range config.Containers {
		for _, entry := range container.Env {
			if entry.Kind != yaml.MappingNode || len(entry.Content) != 2 || entry.Content[1].Tag != "!!str" {
				return nil, errors.New("workload requires explicit measured environment mappings")
			}
			name, value := entry.Content[0].Value, entry.Content[1].Value
			if seen[name] {
				return nil, fmt.Errorf("workload environment %s is ambiguous", name)
			}
			seen[name], values[name] = true, value
		}
	}
	return values, nil
}
