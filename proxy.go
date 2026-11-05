package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tinfoil-go"
)

func setupLogger(streams commandIO, proxyOpts *proxyOptions, verbose, trace bool) *log.Logger {
	logger := log.New()
	logger.SetOutput(streams.err)
	if trace {
		logger.SetLevel(log.TraceLevel)
	} else if verbose {
		logger.SetLevel(log.InfoLevel)
	}

	if proxyOpts.logFormat == "json" {
		logger.SetFormatter(&log.JSONFormatter{})
	} else {
		logger.SetFormatter(&log.TextFormatter{})
	}
	return logger
}

func newProxyCommand(proxyOpts *proxyOptions, rootOpts *rootOptions) *cobra.Command {
	proxyCmd := &cobra.Command{
		Use:        "proxy",
		Short:      "Run a local HTTP proxy",
		Deprecated: "the proxy has moved to github.com/tinfoilsh/tinfoil-proxy. Install the Tinfoil Tray app for a menu-bar UI, or run `go install github.com/tinfoilsh/tinfoil-proxy@latest` for the standalone `tinfoil-proxy` binary.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProxy(proxyOpts, rootOpts, cmd, args)
		},
	}
	proxyCmd.Flags().UintVarP(&proxyOpts.listenPort, "port", "p", 8080, "Port to listen on")
	proxyCmd.Flags().StringVarP(&proxyOpts.listenAddr, "bind", "b", "127.0.0.1", "Address to bind to")
	proxyCmd.Flags().StringVar(&proxyOpts.logFormat, "log-format", "text", "Log format: text or json")
	return proxyCmd
}

func runProxy(proxyOpts *proxyOptions, rootOpts *rootOptions, cmd *cobra.Command, args []string) error {
	options := *rootOpts
	rootOpts = &options
	if (rootOpts.enclaveHost == "") != (rootOpts.repo == "" && rootOpts.localConfigFile == "") {
		return fmt.Errorf("--enclave and either --repo or --config must be supplied together for a custom proxy target")
	}
	verbose, _ := cmd.Flags().GetBool("verbose")
	trace, _ := cmd.Flags().GetBool("trace")
	logger := setupLogger(commandStreams(cmd), proxyOpts, verbose, trace)

	logger.WithFields(log.Fields{
		"enclave_host": rootOpts.enclaveHost,
		"repo":         rootOpts.repo,
	}).Info("initializing secure client")

	var httpClient *http.Client
	var err error
	if rootOpts.enclaveHost == "" && rootOpts.repo == "" {
		var router *tinfoil.RouterHTTPClient
		router, err = tinfoil.NewRouterHTTPClient(cmd.Context(), nil)
		if err == nil {
			rootOpts.enclaveHost = router.Enclave()
			rootOpts.repo = router.Repo()
			httpClient = router.Client
		}
	} else if client := rootOpts.dependencies.proxyClient; client != nil {
		httpClient, err = client(cmd.Context(), rootOpts.enclaveHost, rootOpts.repo)
	} else {
		opts, parseErr := verificationOptions(rootOpts, rootOpts.repo, "")
		if parseErr != nil {
			return parseErr
		}
		var enclave *tinfoil.EnclaveHTTPClient
		enclave, err = tinfoil.NewEnclaveHTTPClient(cmd.Context(), rootOpts.enclaveHost, rootOpts.repo, opts)
		if err == nil {
			httpClient = enclave.Client
		}
	}
	if err != nil {
		return err
	}
	logger.Debug("secure HTTP client created successfully")

	targetUrl, err := url.Parse("https://" + rootOpts.enclaveHost)
	if err != nil {
		return err
	}

	proxy := httputil.NewSingleHostReverseProxy(targetUrl)
	proxy.Transport = withLoggingTransport(logger, httpClient.Transport)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})

	addr := net.JoinHostPort(proxyOpts.listenAddr, strconv.FormatUint(uint64(proxyOpts.listenPort), 10))
	logger.WithFields(log.Fields{
		"address":      addr,
		"enclave_host": rootOpts.enclaveHost,
	}).Info("starting HTTP proxy server")
	serve := rootOpts.dependencies.serveProxy
	if serve == nil {
		serve = http.ListenAndServe
	}
	return serve(addr, mux)
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
