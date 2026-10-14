package main

import (
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
	"net/http"
	"time"
)

func containerNamed(client *cpClient, name string) (containerView, error) {
	var rows []containerView
	if _, err := client.do("GET", "/api/containers", nil, nil, &rows); err != nil {
		return containerView{}, err
	}
	for _, row := range rows {
		if row.Name == name && !row.Debug {
			_, err := client.do("GET", pathf("/api/containers/%s", row.ID), nil, nil, &row)
			return row, err
		}
	}
	return containerView{}, &cpError{Status: http.StatusNotFound, Message: "container not found"}
}

// The controlplane supplies the config; tinfoil-go verifies its endorsement and
// measured digest before a connection can carry owner credentials.
func workloadSource(row containerView, repo string) (string, error) {
	if row.Repo != repo || row.Debug || row.Config == "" {
		return "", errors.New("unexpected workload configuration")
	}
	if _, err := measuredEnvironment(row.Config); err != nil {
		return "", err
	}
	digest := storageHash([]byte(row.Config))
	if row.ConfigName != "/tinfoil/containers/"+digest {
		return "", errors.New("workload config reference does not match its digest")
	}
	target, err := parseConnectionDescriptor(connectionDescriptor{URL: "https://" + row.Domain, ConfigName: row.ConfigName, ConfigDigest: digest})
	return target.source, err
}

func missingContainer(err error) bool {
	var missing *cpError
	return errors.As(err, &missing) && missing.Status == http.StatusNotFound
}

func waitWorkload(client *cpClient, row containerView, status string, timeout time.Duration) (containerView, error) {
	deadline := time.Now().Add(timeout)
	for row.Status != status {
		if row.Status == "failed" || time.Now().After(deadline) {
			return row, fmt.Errorf("%s is %s: %s", row.Name, row.Status, row.ErrorMessage)
		}
		time.Sleep(2 * time.Second)
		if _, err := client.do("GET", pathf("/api/containers/%s", row.ID), nil, nil, &row); err != nil {
			return row, err
		}
	}
	return row, nil
}

func namedWorkload(run func(string) error) func(*cobra.Command, []string) error {
	return func(_ *cobra.Command, args []string) error {
		name, err := sandboxName(args[0])
		if err != nil {
			return err
		}
		return run(name)
	}
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
