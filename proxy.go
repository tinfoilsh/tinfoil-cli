package main

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/tinfoilsh/verifier/client"
)

var (
	listenPort uint
	listenAddr string
)

func init() {
	rootCmd.AddCommand(proxyCmd)
	proxyCmd.Flags().UintVarP(&listenPort, "port", "p", 8080, "Port to listen on")
	proxyCmd.Flags().StringVarP(&listenAddr, "bind", "b", "127.0.0.1", "Address to bind to")
}

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Run a local HTTP proxy",
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Printf("Creating secure client for %s on %s", enclaveHost, repo)
		secureClient := client.NewSecureClient(enclaveHost, repo)
		httpClient, err := secureClient.HTTPClient()
		if err != nil {
			return err
		}

		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			upstreamURL, err := url.Parse("https://" + enclaveHost)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			upstreamURL.Path = r.URL.Path

			outReq, err := http.NewRequest(r.Method, upstreamURL.String(), r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			for name, values := range r.Header {
				for _, value := range values {
					outReq.Header.Add(name, value)
				}
			}

			resp, err := httpClient.Do(outReq)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()

			for name, values := range resp.Header {
				for _, value := range values {
					w.Header().Add(name, value)
				}
			}

			w.WriteHeader(resp.StatusCode)
			if _, err := io.Copy(w, resp.Body); err != nil {
				log.Errorf("Error copying response: %v", err)
			}
		})

		addr := net.JoinHostPort(listenAddr, strconv.FormatUint(uint64(listenPort), 10))
		log.Infof("Starting HTTP proxy on %s", addr)
		return http.ListenAndServe(addr, nil)
	},
}
