package main

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

var body string

func init() {
	httpPostCmd.Flags().StringVarP(&body, "body", "b", "", "HTTP POST body")
	httpCmd.AddCommand(httpPostCmd)
}

var httpPostCmd = &cobra.Command{
	Use:   "post [url]",
	Short: "HTTP POST request",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		resp, err := secureClient().Post(args[0], nil, []byte(body))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(resp.Body))
	},
}
