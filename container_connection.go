package main

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
)

const (
	maxConnectionPort       = 65535
	maxDNSNameLength        = 253
	maxDNSLabelLength       = 63
	pendingDeploymentPrefix = "pending:"
)

type connectionDescriptor struct {
	URL  string `json:"url"`
	Repo string `json:"repo"`
	Tag  string `json:"tag"`
}

type containerConnections struct {
	Production *connectionDescriptor `json:"production"`
	Review     *connectionDescriptor `json:"review"`
}

type verifiedConnection struct {
	connectionDescriptor
	host   string
	source string
}

func containerConnection(c containerView, review bool, sourceOverride string) (verifiedConnection, error) {
	label := "production"
	var descriptor *connectionDescriptor
	if c.Connections != nil {
		descriptor = c.Connections.Production
	}
	if review {
		label = "review"
		descriptor = nil
		if c.Connections != nil && (c.UpdateStatus == statusStarted || c.UpdateStatus == updateStatusReady) &&
			strings.TrimSpace(c.UpdateDeploymentID) != "" && !strings.HasPrefix(c.UpdateDeploymentID, pendingDeploymentPrefix) &&
			c.UpdateTag != "" && c.UpdateType == updateStrategyBlueGreen {
			descriptor = c.Connections.Review
		}
	}
	if descriptor == nil {
		return verifiedConnection{}, fmt.Errorf("container %s has no available %s connection; inspect with: tinfoil container get %s", c.Name, label, shellQuote(c.ID))
	}
	target, err := parseConnectionDescriptor(*descriptor)
	if err != nil {
		return target, fmt.Errorf("invalid %s connection for %s: %w", label, c.Name, err)
	}
	if review && descriptor.Tag != c.UpdateTag {
		return target, fmt.Errorf("review release does not match the current candidate; refresh with: tinfoil container get %s", shellQuote(c.ID))
	}
	if sourceOverride != "" {
		ownerRepo, tag, _, err := provenance.ParseReference(sourceOverride)
		if err != nil {
			return target, fmt.Errorf("--repo: %w", err)
		}
		if review && (ownerRepo != descriptor.Repo || tag != descriptor.Tag) {
			return target, fmt.Errorf("--review requires --repo %s@%s (optionally with @sha256:digest); refusing a different or unpinned release", descriptor.Repo, descriptor.Tag)
		}
		target.source = sourceOverride
	}
	return target, nil
}

func parseConnectionDescriptor(descriptor connectionDescriptor) (verifiedConnection, error) {
	target := verifiedConnection{connectionDescriptor: descriptor}
	u, err := url.Parse(descriptor.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		!validConnectionHost(u.Hostname()) {
		return target, fmt.Errorf("invalid HTTPS URL/host %q", descriptor.URL)
	}
	if port := u.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > maxConnectionPort {
			return target, fmt.Errorf("invalid HTTPS port in %q", descriptor.URL)
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return target, fmt.Errorf("invalid HTTPS port in %q", descriptor.URL)
	}
	target.host = u.Host
	target.source = descriptor.Repo + "@" + descriptor.Tag
	parsedRepo, parsedTag, digest, err := provenance.ParseReference(target.source)
	if err != nil || parsedRepo != descriptor.Repo || parsedTag != descriptor.Tag || parsedTag == "" || digest != "" {
		return target, fmt.Errorf("invalid expected repository/tag %q", target.source)
	}
	return target, nil
}

func validConnectionHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) == 0 || len(host) > maxDNSNameLength {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > maxDNSLabelLength || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if ch != '-' && !(ch >= 'a' && ch <= 'z') && !(ch >= 'A' && ch <= 'Z') && !(ch >= '0' && ch <= '9') {
				return false
			}
		}
	}
	return true
}

func printContainerConnections(out io.Writer, c containerView) {
	for _, review := range []bool{false, true} {
		label, flag := "Production", ""
		if review {
			label, flag = "Review", " --review"
		}
		target, err := containerConnection(c, review, "")
		if err != nil {
			if c.Connections != nil && (review && c.Connections.Review != nil || !review && c.Connections.Production != nil) || review && heldCandidateReady(c) {
				fmt.Fprintf(out, "%s unavailable: %s\n", label, err)
			}
			continue
		}
		fmt.Fprintf(out, "%s URL: %s\nExpected source: %s\n", label, target.URL, target.source)
		fmt.Fprintf(out, "Verified request: tinfoil http get %s --enclave %s --repo %s\n", shellQuote(target.URL), shellQuote(target.host), shellQuote(target.source))
		fmt.Fprintf(out, "Verified proxy: tinfoil container connect %s%s\n", shellQuote(c.ID), flag)
	}
}
