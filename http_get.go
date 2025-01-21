package main

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

func init() {
	httpCmd.AddCommand(httpGetCmd)
}

var httpGetCmd = &cobra.Command{
	Use:   "get [url]",
	Short: "HTTP GET request",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		resp, err := secureClient().Get(args[0], nil)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(resp.Body))
	},
}
