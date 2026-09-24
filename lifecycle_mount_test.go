package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestMountTerminologyPreservesVolumeWireFields(t *testing.T) {
	var c containerView
	if err := json.Unmarshal([]byte(`{"id":"`+testContainerID+`","name":"app","volume_slots":[{"name":"data","key_secret":"KEY"}],"volumes":{"data":"`+testVolumeID+`"}}`), &c); err != nil {
		t.Fatal(err)
	}
	var v volumeView
	if err := json.Unmarshal([]byte(testVolumeRow(true)), &v); err != nil {
		t.Fatal(err)
	}
	if len(c.VolumeSlots) != 1 || c.VolumeSlots[0].Name != "data" || v.Slot != "data" {
		t.Fatal("volume wire fields were not decoded")
	}
	attached := containerVolumes(c, []volumeView{v})
	if attached["data"].ID != testVolumeID {
		t.Fatalf("assignment lost: %v", attached)
	}
	previous := outputFormat
	t.Cleanup(func() { outputFormat = previous })
	outputFormat = "json"
	out, err := captureTestStdout(func() error { return renderContainer(c) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"volume_slots"`) || strings.Contains(string(out), `"mounts"`) {
		t.Fatalf("container wire contract changed: %s", out)
	}
	out, err = captureTestStdout(func() error { return renderVolume(v) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"slot": "data"`) {
		t.Fatalf("volume wire contract changed: %s", out)
	}
	outputFormat = "table"
	for _, message := range []string{
		`select a volume for required slot "data" before starting`,
		"detach the volume before removing its config slot",
		"no volume is attached to this slot",
		"config does not declare this volume slot",
		"volume or slot is already in use",
	} {
		cp := &cpError{Status: http.StatusConflict, Message: message}
		if strings.Contains(cp.Error(), "slot") || !strings.Contains(cp.Error(), "mount") {
			t.Fatalf("human API error = %v", cp)
		}
		c.ErrorMessage = message
		out, err = captureTestStdout(func() error { return renderContainer(c) })
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), "slot") {
			t.Fatalf("human container output = %s", out)
		}
	}
	c.VolumeSlots = append(c.VolumeSlots, volumeSlot{Name: "cache"})
	hint := withAttachHint(&cpError{Status: http.StatusBadRequest, Message: `select a volume for required slot "cache" before starting`}, &c)
	if strings.Contains(hint.Error(), "slot") || !strings.Contains(hint.Error(), "--as cache") {
		t.Fatalf("mount recovery hint = %v", hint)
	}
	for _, command := range []*cobra.Command{containerCreateCmd, containerDeployCmd, volumeAttachCmd} {
		for _, alias := range command.Aliases {
			if strings.Contains(alias, "mount") || strings.Contains(alias, "slot") {
				t.Fatalf("unexpected alias %q", alias)
			}
		}
		help := command.Short + command.Long + command.Flags().FlagUsages()
		if strings.Contains(help, "slot") || !strings.Contains(help, "mount") {
			t.Fatalf("help for %s = %s", command.Name(), help)
		}
	}
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(readme)), "slot") {
		t.Fatal("README uses slot instead of mount")
	}
}
