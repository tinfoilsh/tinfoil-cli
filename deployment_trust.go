package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"golang.org/x/term"
)

const (
	updatesFollow            = "follow"
	updatesAsk               = "ask"
	updatesPinned            = "pinned"
	knownDeploymentsFileName = "known-deployments.jsonl"
	envKnownDeployments      = "TINFOIL_KNOWN_DEPLOYMENTS"
	enclaveHTTPSPort         = "443"
	localConfigProject       = "local"
)

type deploymentRecord struct {
	Host    string `json:"host"`
	Scope   string `json:"scope,omitempty"`
	Project string `json:"project"`
	Digest  string `json:"digest"`
}

func validateUpdates(mode string) error {
	switch mode {
	case updatesFollow, updatesAsk, updatesPinned:
		return nil
	default:
		return fmt.Errorf("unknown update policy %q: use follow, ask, or pinned", mode)
	}
}

func deploymentHost(host string) (string, error) {
	endpoint, err := url.Parse("https://" + host)
	if err != nil || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return "", fmt.Errorf("invalid deployment endpoint %q", host)
	}
	port := endpoint.Port()
	if port == "" {
		port = enclaveHTTPSPort
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > maxConnectionPort {
		return "", fmt.Errorf("invalid deployment port %q", port)
	}
	return net.JoinHostPort(strings.ToLower(endpoint.Hostname()), strconv.Itoa(number)), nil
}

func knownDeploymentsPath() (string, error) {
	if path := os.Getenv(envKnownDeployments); path != "" {
		return path, nil
	}
	policy, err := connectionPolicyPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(policy), knownDeploymentsFileName), nil
}

func readDeployments(path string) (map[string]deploymentRecord, error) {
	records := map[string]deploymentRecord{}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return records, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var record deploymentRecord
		if err := json.Unmarshal(scanner.Bytes(), &record, json.RejectUnknownMembers(true)); err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		host, err := deploymentHost(record.Host)
		digest, decodeErr := hex.DecodeString(record.Digest)
		if err != nil || host != record.Host || len(digest) != sha256.Size || decodeErr != nil || strings.ToLower(record.Digest) != record.Digest {
			return nil, fmt.Errorf("invalid deployment record in %s", path)
		}
		if record.Scope != "" {
			if err := configendorsement.ValidateScope(record.Scope); err != nil {
				return nil, err
			}
		}
		if record.Project != localConfigProject {
			project, tag, pin, err := verify.ParseReference(record.Project)
			if err != nil || project != record.Project || tag != "" || pin != "" {
				return nil, fmt.Errorf("invalid deployment project in %s", path)
			}
		}
		if _, exists := records[host]; exists {
			return nil, fmt.Errorf("duplicate deployment %s in %s", host, path)
		}
		records[host] = record
	}
	return records, scanner.Err()
}

func writeDeploymentRecords(out io.Writer, records map[string]deploymentRecord) error {
	hosts := make([]string, 0, len(records))
	for host := range records {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		data, err := json.Marshal(records[host])
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(out, string(data)); err != nil {
			return err
		}
	}
	return nil
}

func saveDeployments(path string, records map[string]deploymentRecord) error {
	var output bytes.Buffer
	if err := writeDeploymentRecords(&output, records); err != nil {
		return err
	}
	return writeAtomic(path, output.Bytes())
}

func lockDeploymentRecords(path string) (func(), error) {
	if err := prepareStorageDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW, storageFileMode)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, err
	}
	return func() { _ = file.Close() }, nil
}

func rememberDeployment(record deploymentRecord, explicitPin bool, mode string, in io.Reader, out io.Writer, interactive bool) error {
	if err := validateUpdates(mode); err != nil {
		return err
	}
	path, err := knownDeploymentsPath()
	if err != nil {
		return err
	}
	unlock, err := lockDeploymentRecords(path)
	if err != nil {
		return err
	}
	defer unlock()
	records, err := readDeployments(path)
	if err != nil {
		return err
	}
	previous, known := records[record.Host]
	if known && (previous.Scope != record.Scope || previous.Project != record.Project) {
		return fmt.Errorf("deployment identity changed for %s: %s (%s) became %s (%s); review it before running tinfoil trust forget %s", record.Host, previous.Project, previous.Scope, record.Project, record.Scope, record.Host)
	}
	if known && previous.Digest == record.Digest {
		return nil
	}
	if !explicitPin {
		switch mode {
		case updatesPinned:
			return fmt.Errorf("deployment %s has an unapproved config digest; pass an explicit --repo digest pin or --config file", record.Host)
		case updatesAsk:
			if !interactive {
				return fmt.Errorf("deployment %s needs config approval; use an interactive connection or an explicit digest pin", record.Host)
			}
			fmt.Fprintf(out, "Deployment: %s\nProject: %s\n", record.Host, record.Project)
			if known {
				fmt.Fprintf(out, "Previous config: sha256:%s\n", previous.Digest)
			}
			fmt.Fprintf(out, "Config: sha256:%s\nAccept this config? [y/N] ", record.Digest)
			scanner := bufio.NewScanner(in)
			if !scanner.Scan() {
				if err := scanner.Err(); err != nil {
					return err
				}
				return fmt.Errorf("config approval declined")
			}
			answer := strings.TrimSpace(scanner.Text())
			if !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
				return fmt.Errorf("config approval declined")
			}
		}
	}
	records[record.Host] = record
	return saveDeployments(path, records)
}

func checkVerifiedDeployment(host, source string, verified *verify.Verification) error {
	if trustDangerous {
		return nil
	}
	endpoint, err := deploymentHost(host)
	if err != nil {
		return err
	}
	record := deploymentRecord{Host: endpoint, Project: verified.ConfigRepo(), Digest: verified.CodeDigest()}
	explicitPin := localConfigFile != ""
	if source != "" {
		_, _, pin, err := verify.ParseReference(source)
		if err != nil {
			return err
		}
		explicitPin = pin != ""
	}
	if config, ok := verified.Config(); ok {
		record.Scope, record.Digest = config.Scope, config.Digest
		if config.Name == "" {
			record.Project = localConfigProject
		} else {
			project, _, err := configendorsement.ParseName(config.Name)
			if err != nil {
				return err
			}
			record.Project = strings.TrimPrefix(project, "/")
		}
	}
	policy, err := loadConnectionPolicy()
	if err != nil {
		return err
	}
	return rememberDeployment(record, explicitPin, policy.Updates, os.Stdin, os.Stderr, term.IsTerminal(int(os.Stdin.Fd())))
}

func init() {
	trustCmd.AddCommand(&cobra.Command{Use: "forget <endpoint>", Short: "Forget a deployment binding without changing trust policy", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		host, err := deploymentHost(args[0])
		if err != nil {
			return err
		}
		path, err := knownDeploymentsPath()
		if err != nil {
			return err
		}
		unlock, err := lockDeploymentRecords(path)
		if err != nil {
			return err
		}
		defer unlock()
		records, err := readDeployments(path)
		if err != nil {
			return err
		}
		if _, exists := records[host]; !exists {
			return fmt.Errorf("no remembered deployment for %s", host)
		}
		delete(records, host)
		return saveDeployments(path, records)
	}})
}
