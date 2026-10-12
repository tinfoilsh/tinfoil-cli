package main

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// renderTemplateEnv binds template inputs to literal, measured container environment
// entries. Supplied values replace defaults declared in containers[].env.
// Unbound names remain runtime environment references.
// The CLI and controlplane reproduce the same measured bytes.
func renderTemplateEnv(raw []byte, values map[string]string) ([]byte, error) {
	if len(raw) > (1 << 20) {
		return nil, fmt.Errorf("template exceeds %d-byte limit", (1 << 20))
	}
	if len(values) == 0 {
		return raw, nil
	}
	var doc yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&doc); err != nil {
		return nil, err
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("template must contain exactly one YAML document")
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("template must be a YAML mapping")
	}
	field := func(node *yaml.Node, name string) *yaml.Node {
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == name {
				return node.Content[i+1]
			}
		}
		return &yaml.Node{}
	}
	bound := make(map[string]int, len(values))
	for _, container := range field(doc.Content[0], "containers").Content {
		for _, entry := range field(container, "env").Content {
			if entry.Kind == yaml.MappingNode {
				for i := 0; i+1 < len(entry.Content); i += 2 {
					name := entry.Content[i].Value
					value, supplied := values[name]
					if !supplied {
						continue
					}
					bound[name]++
					if entry.Content[i+1].Value != value {
						entry.Content[i+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value, Style: yaml.DoubleQuotedStyle}
					}
				}
				continue
			}
			name, previous, hasValue := strings.Cut(entry.Value, "=")
			value, supplied := values[name]
			if !supplied {
				continue
			}
			bound[name]++
			if hasValue && previous == value {
				continue
			}
			entry.Kind, entry.Tag, entry.Value, entry.Style = yaml.MappingNode, "!!map", "", 0
			entry.Content = []*yaml.Node{
				{Kind: yaml.ScalarNode, Tag: "!!str", Value: name},
				{Kind: yaml.ScalarNode, Tag: "!!str", Value: value, Style: yaml.DoubleQuotedStyle},
			}
		}
	}
	for name := range values {
		if bound[name] != 1 {
			return nil, fmt.Errorf("template parameter %q must appear exactly once", name)
		}
	}
	return yaml.Marshal(&doc)
}
