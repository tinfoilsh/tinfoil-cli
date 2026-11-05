package main

import (
	"github.com/spf13/cobra"
)

func newHttpGetCommand(headersOpts *headersOptions, rootOpts *rootOptions) *cobra.Command {
	httpGetCmd := &cobra.Command{
		Use:   "get [url]",
		Short: "HTTP GET request",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			headers, err := parseRequestHeaders(headersOpts.requestHeaders)
			if err != nil {
				return err
			}

			sc, err := secureClient(rootOpts)
			if err != nil {
				return err
			}
			resp, err := requestWithHeaders(sc, "GET", args[0], headers, nil)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			return printHTTPResponse(cmd.OutOrStdout(), resp.Body)
		},
	}

	return httpGetCmd
}
