package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	httpCmd.AddCommand(httpGetCmd)
}

var httpGetCmd = &cobra.Command{
	Use:   "get [url]",
	Short: "HTTP GET request",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		headers, err := parseRequestHeaders(requestHeaders)
		if err != nil {
			return err
		}

		resp, err := secureClient().Get(args[0], headers)
		if err != nil {
			return err
		}
		fmt.Println(string(resp.Body))
		return nil
	},
}
