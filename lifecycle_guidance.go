package main

import (
	"fmt"
	"io"
	"strings"
)

func shellQuote(value string) string {
	if value != "" && !strings.ContainsAny(value, " \t\r\n'\"`$;&|<>*?(){}[]!\\") && !strings.HasPrefix(value, "-") {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func printVolumeUnlockGuidance(out io.Writer, mounts []volumeSlot) {
	for _, mount := range mounts {
		if mount.KeySecret != "" {
			fmt.Fprintf(out, "Mount %s: automatic unlock requires keyserver configuration and secret %s outside Tinfoil; attaching a disk does not establish unlock readiness.\n", mount.Name, mount.KeySecret)
		} else {
			fmt.Fprintf(out, "Mount %s: optional/manual unlock; an attached disk still needs workload-managed initialization and unlocking.\n", mount.Name)
		}
	}
}
