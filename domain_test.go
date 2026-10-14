package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRenderDomainListsBothCNAMERecords(t *testing.T) {
	var d domainView
	if err := json.Unmarshal([]byte(`{
		"domain": "api.example.com",
		"verified": false,
		"txt_record_host": "_tinfoil.api.example.com",
		"txt_record_value": "tf-domain-verify=api.example.com,nonce",
		"cname_target": "abc123.tf-dns.com",
		"cname_configured": true,
		"acme_challenge_host": "_acme-challenge.api.example.com",
		"acme_challenge_target": "acme-abc123.tf-dns.com",
		"acme_challenge_configured": false
	}`), &d); err != nil {
		t.Fatal(err)
	}
	saved := outputFormat
	outputFormat = "table"
	t.Cleanup(func() { outputFormat = saved })
	captured, err := captureTestStdout(func() error {
		return renderDomain(d, true)
	})
	if err != nil {
		t.Fatal(err)
	}
	out := string(captured)
	for _, want := range []string{
		"  CNAME  api.example.com  =>  abc123.tf-dns.com\n",
		"  CNAME  _acme-challenge.api.example.com  =>  acme-abc123.tf-dns.com\n",
		"Traffic CNAME currently observed: true\n",
		"Certificate CNAME currently observed: false\n",
		"after the _acme-challenge.api.example.com CNAME propagates",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "_tinfoil") {
		t.Errorf("output still asks for the TXT record:\n%s", out)
	}
}
