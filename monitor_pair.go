package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// Only creation pairs keys. Policy stays opaque except for identity keys and route access.
func pairSandboxMonitor(client *ssh.Client, dir, name, device, agent string) error {
	var view map[string]any
	if err := monitorOwnerRequest(client, dir, "GET", "/", nil, &view); err != nil {
		return err
	}
	config, ok := view["config"].(map[string]any)
	generation, hasGeneration := view["generation"].(json.Number)
	if !ok || !hasGeneration {
		return errors.New("Monitor response has no config or generation")
	}
	identities, _ := config["identities"].(map[string]any)
	var changes []map[string]any
	for label, identity := range map[string]map[string]any{
		"device-" + storageHash([]byte(device))[:16]: {"key": device, "routes": true},
		"sandbox-" + name: {"key": agent},
	} {
		found := false
		for existingName, raw := range identities {
			existing, _ := raw.(map[string]any)
			key, _ := existing["key"].(string)
			if sameSSHKey(key, identity["key"].(string)) {
				if identity["routes"] == true && existing["routes"] != true {
					return fmt.Errorf("Monitor identity %s has sandbox routes disabled; enable them in the Monitor UI", existingName)
				}
				found = true
			}
		}
		if found {
			continue
		}
		if _, exists := identities[label]; exists {
			return fmt.Errorf("Monitor identity %s belongs to another key", label)
		}
		changes = append(changes, map[string]any{"path": []string{"identities", label}, "value": identity})
	}
	if len(changes) == 0 {
		return nil
	}
	return monitorOwnerRequest(client, dir, "POST", "/policy/edits", map[string]any{
		"generation": generation, "changes": changes,
	}, nil)
}
