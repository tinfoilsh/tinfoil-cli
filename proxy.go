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
	logFormat  string
)

func init() {
	rootCmd.AddCommand(proxyCmd)
	proxyCmd.Flags().UintVarP(&listenPort, "port", "p", 8080, "Port to listen on")
	proxyCmd.Flags().StringVarP(&listenAddr, "bind", "b", "127.0.0.1", "Address to bind to")
	proxyCmd.Flags().StringVar(&logFormat, "log-format", "text", "Log format: text or json")
}

func setupLogger(verbose, trace bool) {
	if trace {
		log.SetLevel(log.TraceLevel)
	} else if verbose {
		log.SetLevel(log.InfoLevel)
	}

	if logFormat == "json" {
		log.SetFormatter(&log.JSONFormatter{})
	} else {
		log.SetFormatter(&log.TextFormatter{})
	}
}

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Run a local HTTP proxy",
	RunE: func(cmd *cobra.Command, args []string) error {
		verbose, _ := cmd.Flags().GetBool("verbose")
		trace, _ := cmd.Flags().GetBool("trace")
		setupLogger(verbose, trace)

		log.WithFields(log.Fields{
			"enclave_host": enclaveHost,
			"repo":         repo,
		}).Info("initializing secure client")
		secureClient := client.NewSecureClient(enclaveHost, repo)
		httpClient, err := secureClient.HTTPClient()
		if err != nil {
			log.WithError(err).Error("failed to create HTTP client")
			return err
		}
		log.Debug("secure HTTP client created successfully")

		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			log.WithFields(log.Fields{
				"method":      r.Method,
				"path":        r.URL.Path,
				"remote_addr": r.RemoteAddr,
			}).Debug("received request")

			upstreamURL, err := url.Parse("https://" + enclaveHost)
			if err != nil {
				log.WithError(err).Error("failed to parse upstream URL")
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			upstreamURL.Path = r.URL.Path

			outReq, err := http.NewRequest(r.Method, upstreamURL.String(), r.Body)
			if err != nil {
				log.WithFields(log.Fields{
					"method": r.Method,
					"url":    upstreamURL.Host + upstreamURL.Path,
				}).WithError(err).Error("failed to create upstream request")
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			for name, values := range r.Header {
				for _, value := range values {
					outReq.Header.Add(name, value)
				}
			}

			log.WithFields(log.Fields{
				"method": outReq.Method,
				"url":    outReq.URL.Host + outReq.URL.Path,
			}).Debug("forwarding request to upstream")

			resp, err := httpClient.Do(outReq)
			if err != nil {
				log.WithFields(log.Fields{
					"method": outReq.Method,
					"url":    outReq.URL.Host + outReq.URL.Path,
				}).WithError(err).Error("upstream request failed")
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()

			log.WithFields(log.Fields{
				"status_code":    resp.StatusCode,
				"content_length": resp.ContentLength,
			}).Debug("received upstream response")

			if resp.StatusCode >= 500 && resp.StatusCode < 600 {
				log.WithFields(log.Fields{
					"status_code": resp.StatusCode,
					"method":      outReq.Method,
					"url":         outReq.URL.Host + outReq.URL.Path,
				}).Warn("upstream server returned error")
			}

			for name, values := range resp.Header {
				for _, value := range values {
					w.Header().Add(name, value)
				}
			}

			w.WriteHeader(resp.StatusCode)
			if _, err := io.Copy(w, resp.Body); err != nil {
				log.WithError(err).Error("failed to copy response body to client")
			}

			log.WithFields(log.Fields{
				"method":      r.Method,
				"path":        r.URL.Path,
				"status_code": resp.StatusCode,
			}).Info("request completed")
		})

		addr := net.JoinHostPort(listenAddr, strconv.FormatUint(uint64(listenPort), 10))
		log.WithFields(log.Fields{
			"address":      addr,
			"enclave_host": enclaveHost,
		}).Info("starting HTTP proxy server")
		return http.ListenAndServe(addr, nil)
	},
}
