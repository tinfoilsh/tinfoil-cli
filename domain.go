package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

type domainView struct {
	ID                      string   `json:"id"`
	Domain                  string   `json:"domain"`
	Wildcard                bool     `json:"wildcard"`
	VerificationNonce       string   `json:"verification_nonce"`
	CnameHash               string   `json:"cname_hash"`
	Verified                bool     `json:"verified"`
	VerifiedAt              *string  `json:"verified_at"`
	CreatedAt               string   `json:"created_at"`
	UsedBy                  []string `json:"used_by"`
	TXTRecordHost           string   `json:"txt_record_host"`
	TXTRecordValue          string   `json:"txt_record_value"`
	CNAMETarget             string   `json:"cname_target"`
	CNAMEConfigured         *bool    `json:"cname_configured"`
	ACMEChallengeHost       string   `json:"acme_challenge_host"`
	ACMEChallengeTarget     string   `json:"acme_challenge_target"`
	ACMEChallengeConfigured *bool    `json:"acme_challenge_configured"`
}

func init() {
	rootCmd.AddCommand(domainCmd)
	domainCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")
	domainCmd.AddCommand(domainListCmd, domainAddCmd, domainVerifyCmd, domainDeleteCmd)
	silenceUsageRecursive(domainCmd)
}

var domainCmd = &cobra.Command{
	Use:          "domain",
	Aliases:      []string{"domains"},
	Short:        "Manage custom domains for containers",
	SilenceUsage: true,
}

var domainListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List custom domains",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		var list []domainView
		if _, err := client.do("GET", "/api/domains", nil, nil, &list); err != nil {
			return err
		}
		if outputFormat == "json" {
			return printJSON(list)
		}
		if len(list) == 0 {
			fmt.Println("No custom domains.")
			return nil
		}
		fmt.Printf("%-40s  %-10s  %-30s  %s\n", "DOMAIN", "VERIFIED", "CNAME TARGET", "USED BY")
		for _, d := range list {
			used := strings.Join(d.UsedBy, ", ")
			if used == "" {
				used = "-"
			}
			fmt.Printf("%-40s  %-10v  %-30s  %s\n",
				truncate(d.Domain, 40), d.Verified, truncate(d.CNAMETarget, 30), used,
			)
		}
		return nil
	},
}

var domainAddCmd = &cobra.Command{
	Use:   "add [domain]",
	Short: "Register a new custom domain (returns DNS records to configure)",
	Long: `Register a new custom domain and print the DNS records to configure.

Most domains do not need a wildcard. Add the domain as '*.example.com'
(quoted, so your shell does not expand it) only when one container serves its
subdomains. This registers example.com and adds a wildcard record. Running it
for an already registered domain adds the wildcard record to that domain.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		body := map[string]any{"domain": args[0]}
		var d domainView
		if _, err := client.do("POST", "/api/domains", nil, body, &d); err != nil {
			return err
		}
		return renderDomain(d, false)
	},
}

var domainVerifyCmd = &cobra.Command{
	Use:   "verify [domain]",
	Short: "Re-check the DNS records and update verification status",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		var d domainView
		if _, err := client.do("POST", pathf("/api/domains/%s/verify", args[0]), nil, nil, &d); err != nil {
			return err
		}
		return renderDomain(d, true)
	},
}

var domainDeleteCmd = &cobra.Command{
	Use:     "delete [domain]",
	Aliases: []string{"rm", "remove"},
	Short:   "Delete a custom domain (fails if any container uses it)",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := authedClient()
		if err != nil {
			return err
		}
		if _, err := client.do("DELETE", pathf("/api/domains/%s", args[0]), nil, nil, nil); err != nil {
			return err
		}
		fmt.Printf("Deleted domain %s\n", args[0])
		return nil
	},
}

func renderDomain(d domainView, verifyMode bool) error {
	if outputFormat == "json" {
		return printJSON(d)
	}
	fmt.Printf("Domain:     %s\n", d.Domain)
	fmt.Printf("Verified:   %v\n", d.Verified)
	if d.VerifiedAt != nil {
		fmt.Printf("Verified at: %s\n", *d.VerifiedAt)
	}
	fmt.Printf("\nConfigure these DNS records on your domain:\n")
	fmt.Printf("  CNAME  %s  =>  %s\n", d.Domain, d.CNAMETarget)
	fmt.Printf("  CNAME  %s  =>  %s\n", d.ACMEChallengeHost, d.ACMEChallengeTarget)
	if d.Wildcard {
		fmt.Printf("  CNAME  *.%s  =>  %s\n", d.Domain, d.CNAMETarget)
		fmt.Printf("\nSubdomains reach the same container, not different ones. Set\nshim.tls-wildcard: true in tinfoil-config.yml so its certificate covers them.\n")
	}
	if verifyMode && d.CNAMEConfigured != nil {
		fmt.Printf("\nTraffic CNAME currently observed: %v\n", *d.CNAMEConfigured)
	}
	if verifyMode && d.ACMEChallengeConfigured != nil {
		fmt.Printf("Certificate CNAME currently observed: %v\n", *d.ACMEChallengeConfigured)
	}
	if !d.Verified {
		fmt.Printf("\nRun `tinfoil domain verify %s` after the %s CNAME propagates.\n", d.Domain, d.ACMEChallengeHost)
	}
	if len(d.UsedBy) > 0 {
		fmt.Printf("\nUsed by: %s\n", strings.Join(d.UsedBy, ", "))
	}
	return nil
}
