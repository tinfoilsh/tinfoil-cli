package policyreference

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Policy is the release-approval boundary. A workload is the build of one
// repository at one pinned release tag; nothing the caller merely asserts
// (repo string, network origin) authorizes anything — the document's
// Sigstore code artifact is authenticated against the pinned repo, and the
// authenticated tag must equal the pin.
type Policy struct {
	Workloads map[string]*Workload `yaml:"workloads"`
}

type Workload struct {
	// Repo and Tag pin the authorized build. Bump the tag to authorize a
	// new release.
	Repo string `yaml:"repo"`
	Tag  string `yaml:"tag"`

	// Domain, when set, additionally requires the caller's TLS certificate
	// to be CA-issued for this domain. This is what stops someone else who
	// deploys the same public repo (identical attested build) from receiving
	// this workload's secrets.
	Domain string `yaml:"domain,omitempty"`

	Secrets map[string]*SecretRef `yaml:"secrets"`
}

type SecretRef struct {
	Path  string `yaml:"path"`
	Field string `yaml:"field"`
}

func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy: %w", err)
	}
	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("parsing policy: %w", err)
	}
	if len(policy.Workloads) == 0 {
		return nil, fmt.Errorf("policy authorizes no workloads")
	}
	pinned := map[string]string{}
	for name, w := range policy.Workloads {
		if w == nil || w.Repo == "" || w.Tag == "" {
			return nil, fmt.Errorf("workload %q needs repo and tag", name)
		}
		pin := w.Repo + "@" + w.Tag
		if other, taken := pinned[pin]; taken {
			return nil, fmt.Errorf("workloads %q and %q pin the same release %s", other, name, pin)
		}
		pinned[pin] = name
		if len(w.Secrets) == 0 {
			return nil, fmt.Errorf("workload %q maps no secrets", name)
		}
		for ref, target := range w.Secrets {
			if target == nil || target.Path == "" || target.Field == "" {
				return nil, fmt.Errorf("workload %q secret %q needs path and field", name, ref)
			}
		}
	}
	return &policy, nil
}

// TrustsRepo reports whether any workload pins the repo, so verification
// only runs for repositories the operator actually trusts.
func (p *Policy) TrustsRepo(repo string) bool {
	for _, w := range p.Workloads {
		if w.Repo == repo {
			return true
		}
	}
	return false
}

// Match selects the workload pinning the authenticated repo@tag.
func (p *Policy) Match(repo, tag string) (string, *Workload) {
	for name, w := range p.Workloads {
		if w.Repo == repo && w.Tag == tag {
			return name, w
		}
	}
	return "", nil
}

// Authorize maps the requested refs against a matched workload. All refs
// must be mapped; release is all-or-nothing so a container never launches
// with a variable silently missing.
func (w *Workload) Authorize(name string, refs []string) (map[string]*SecretRef, error) {
	if len(refs) == 0 {
		return nil, fmt.Errorf("no secrets requested")
	}
	release := make(map[string]*SecretRef, len(refs))
	for _, ref := range refs {
		target, ok := w.Secrets[ref]
		if !ok {
			return nil, fmt.Errorf("secret %q is not authorized for workload %q", ref, name)
		}
		release[ref] = target
	}
	return release, nil
}
