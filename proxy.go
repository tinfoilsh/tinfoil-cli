package main

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tinfoil-go"
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

		targetUrl, err := url.Parse("https://" + enclaveHost)
		if err != nil {
			log.WithError(err).Error("failed to parse upstream URL")
			return err
		}

		log.WithFields(log.Fields{
			"enclave_host": enclaveHost,
			"repo":         repo,
		}).Info("initializing secure client")

		tinfoilClient, err := tinfoil.NewClientWithParams(enclaveHost, repo)
		if err != nil {
			log.WithError(err).Error("failed to create HTTP client")
			return err
		}
		log.Debug("secure HTTP client created successfully")

		httpClient := tinfoilClient.HTTPClient()

		proxy := httputil.NewSingleHostReverseProxy(targetUrl)
		proxy.Transport = withLoggingTransport(log.StandardLogger(), httpClient.Transport)

		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			proxy.ServeHTTP(w, r)
		})

		addr := net.JoinHostPort(listenAddr, strconv.FormatUint(uint64(listenPort), 10))
		log.WithFields(log.Fields{
			"address":      addr,
			"enclave_host": enclaveHost,
		}).Info("starting HTTP proxy server")
		return http.ListenAndServe(addr, nil)
	},
}

func withLoggingTransport(logger *log.Logger, base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}

	return &loggingTransport{
		wrapped: base,
		logger:  logger,
	}
}

// loggingTransport implements http.RoundTripper and wraps an existing
// transport with logging functions
type loggingTransport struct {
	wrapped http.RoundTripper
	logger  *log.Logger
}

func (lt *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	lt.logger.WithFields(log.Fields{
		"method": req.Method,
		"host":   req.URL.Host,
		"path":   req.URL.Path,
	}).Debug("Outgoing request to upstream")

	// Send the request
	resp, err := lt.wrapped.RoundTrip(req)
	if err != nil {
		lt.logger.WithFields(log.Fields{
			"method": req.Method,
			"host":   req.URL.Host,
			"path":   req.URL.Path,
		}).Error("Request to upstream failed")
		return nil, err
	}

	logEntry := lt.logger.WithFields(log.Fields{
		"method": req.Method,
		"target": req.URL.Host,
		"path":   req.URL.Path,
		"status": resp.Status,
		"size":   resp.ContentLength,
	})

	switch {
	case resp.StatusCode >= 500:
		logEntry.Warn("Upstream server error")
	case resp.StatusCode >= 400:
		logEntry.Warn("Upstream client error")
	default:
		logEntry.Info("Upstream request complete")
	}

	return resp, err
}
