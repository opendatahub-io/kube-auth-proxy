package http

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/options"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/options/util"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/logger"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/tls/profile"
)

// Server represents an HTTP or HTTPS server.
type Server interface {
	// Start blocks and runs the server.
	Start(ctx context.Context) error
}

// Opts contains the information required to set up the server.
type Opts struct {
	// Handler is the http.Handler to be used to serve http pages by the server.
	Handler http.Handler

	// BindAddress is the address the HTTP server should listen on.
	BindAddress string

	// SecureBindAddress is the address the HTTPS server should listen on.
	SecureBindAddress string

	// TLS is the TLS configuration for the server.
	TLS *options.TLS

	// TLSProfileManager manages dynamic TLS configuration from OpenShift
	TLSProfileManager profile.Manager

	// Let testing infrastructure circumvent parsing file descriptors
	fdFiles []*os.File
}

// NewServer creates a new Server from the options given.
func NewServer(opts Opts) (Server, error) {
	s := &server{
		handler:           opts.Handler,
		tlsProfileManager: opts.TLSProfileManager,
	}

	if len(opts.fdFiles) > 0 {
		s.fdFiles = opts.fdFiles
	}

	if err := s.setupListener(opts); err != nil {
		return nil, fmt.Errorf("error setting up listener: %v", err)
	}
	if err := s.setupTLSListener(opts); err != nil {
		return nil, fmt.Errorf("error setting up TLS listener: %v", err)
	}

	return s, nil
}

// server is an implementation of the Server interface.
type server struct {
	handler http.Handler

	listener    net.Listener
	tlsListener net.Listener

	// TLS configuration management
	tlsProfileManager profile.Manager
	tlsConfig         *tls.Config
	tlsConfigMutex    sync.RWMutex

	// ensure activation.Files are called once
	fdFiles []*os.File
}

// setupListener sets the server listener if the HTTP server is enabled.
// The HTTP server can be disabled by setting the BindAddress to "-" or by
// leaving it empty.
func (s *server) setupListener(opts Opts) error {
	if opts.BindAddress == "" || opts.BindAddress == "-" {
		// No HTTP listener required
		return nil
	}

	// Use fd: as a prefix for systemd socket activation, it's generic
	// enough and short.
	// The most common usage would be --http-address fd:3.
	// This causes oauth2-proxy to just assume that the third fd passed
	// to the program is indeed a net.Listener and starts using it
	// without setting up a new listener.
	if strings.HasPrefix(strings.ToLower(opts.BindAddress), "fd:") {
		return s.checkSystemdSocketSupport(opts)
	}

	networkType := getNetworkScheme(opts.BindAddress)
	listenAddr := getListenAddress(opts.BindAddress)

	listener, err := net.Listen(networkType, listenAddr)
	if err != nil {
		return fmt.Errorf("listen (%s, %s) failed: %w", networkType, listenAddr, err)
	}
	s.listener = listener

	return nil
}

func parseCipherSuites(names []string) ([]uint16, error) {
	cipherNameMap := make(map[string]uint16)

	for _, cipherSuite := range tls.CipherSuites() {
		cipherNameMap[cipherSuite.Name] = cipherSuite.ID
	}
	for _, cipherSuite := range tls.InsecureCipherSuites() {
		cipherNameMap[cipherSuite.Name] = cipherSuite.ID
	}

	result := make([]uint16, len(names))
	for i, name := range names {
		id, present := cipherNameMap[name]
		if !present {
			return nil, fmt.Errorf("unknown TLS cipher suite name specified %q", name)
		}
		result[i] = id
	}
	return result, nil
}

// setupTLSListener sets the server TLS listener if the HTTPS server is enabled.
// The HTTPS server can be disabled by setting the SecureBindAddress to "-" or by
// leaving it empty.
func (s *server) setupTLSListener(opts Opts) error {
	if opts.SecureBindAddress == "" || opts.SecureBindAddress == "-" {
		// No HTTPS listener required
		return nil
	}

	if opts.TLS == nil {
		return errors.New("no TLS config provided")
	}

	// Get TLS configuration from profile manager if available
	var tlsConfig *tls.Config
	if s.tlsProfileManager != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		profileConfig, err := s.tlsProfileManager.GetTLSConfig(ctx)
		if err != nil {
			logger.Errorf("Failed to generate TLS configuration from APIServer.tlsSecurityProfile, falling back to default: %v", err)
			// Fall back to default configuration
			tlsConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS13,
				NextProtos: []string{"http/1.1"},
			}
		} else {
			tlsConfig = profileConfig
			logger.Printf("Using TLS configuration generated from APIServer.tlsSecurityProfile: MinVersion=0x%x, MaxVersion=0x%x",
				tlsConfig.MinVersion, tlsConfig.MaxVersion)
		}
	} else {
		// Legacy behavior with hardcoded config for backward compatibility
		var legacyErr error
		tlsConfig, legacyErr = s.buildLegacyTLSConfig(opts.TLS)
		if legacyErr != nil {
			return legacyErr
		}
	}

	// Load certificate
	cert, err := getCertificate(opts.TLS)
	if err != nil {
		return fmt.Errorf("could not load certificate: %v", err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	// Store the TLS config for dynamic updates
	s.tlsConfigMutex.Lock()
	s.tlsConfig = tlsConfig
	s.tlsConfigMutex.Unlock()

	// Create listener
	listenAddr := getListenAddress(opts.SecureBindAddress)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen (%s) failed: %v", listenAddr, err)
	}

	// Create dynamic TLS listener that uses our managed config
	s.tlsListener = tls.NewListener(tcpKeepAliveListener{listener.(*net.TCPListener)}, s.getDynamicTLSConfig())

	return nil
}

// buildLegacyTLSConfig creates TLS config using the legacy hardcoded approach for backward compatibility
func (s *server) buildLegacyTLSConfig(opts *options.TLS) (*tls.Config, error) {
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
	}

	if len(opts.CipherSuites) > 0 {
		cipherSuites, err := parseCipherSuites(opts.CipherSuites)
		if err != nil {
			return nil, fmt.Errorf("could not parse cipher suites: %v", err)
		}
		config.CipherSuites = cipherSuites
	}

	if len(opts.MinVersion) > 0 {
		switch opts.MinVersion {
		case "TLS1.2":
			config.MinVersion = tls.VersionTLS12
		case "TLS1.3":
			config.MinVersion = tls.VersionTLS13
		default:
			return nil, fmt.Errorf("unknown TLS MinVersion config provided: %s", opts.MinVersion)
		}
	}

	return config, nil
}

// getDynamicTLSConfig returns a copy of the current TLS config with GetConfigForClient callback
// This enables dynamic TLS config updates without restarting the listener
func (s *server) getDynamicTLSConfig() *tls.Config {
	s.tlsConfigMutex.RLock()
	config := s.tlsConfig.Clone()
	s.tlsConfigMutex.RUnlock()

	// Set up dynamic config callback
	config.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		s.tlsConfigMutex.RLock()
		defer s.tlsConfigMutex.RUnlock()
		return s.tlsConfig.Clone(), nil
	}

	return config
}

// Start starts the HTTP and HTTPS server if applicable.
// It will block until the context is cancelled.
// If any errors occur, only the first error will be returned.
func (s *server) Start(ctx context.Context) error {
	g, groupCtx := errgroup.WithContext(ctx)

	// Start TLS profile watcher if we have a profile manager and TLS listener
	if s.tlsProfileManager != nil && s.tlsListener != nil {
		g.Go(func() error {
			return s.startTLSWatcher(groupCtx)
		})
	}

	if s.listener != nil {
		g.Go(func() error {
			if err := s.startServer(groupCtx, s.listener); err != nil {
				return fmt.Errorf("error starting insecure server: %v", err)
			}
			return nil
		})
	}

	if s.tlsListener != nil {
		g.Go(func() error {
			if err := s.startServer(groupCtx, s.tlsListener); err != nil {
				return fmt.Errorf("error starting secure server: %v", err)
			}
			return nil
		})
	}

	return g.Wait()
}

// startTLSWatcher starts watching for TLS profile changes and updates the configuration dynamically
func (s *server) startTLSWatcher(ctx context.Context) error {
	logger.Printf("Starting TLS profile watcher")

	callback := s.updateTLSConfig
	if err := s.tlsProfileManager.StartWatching(ctx, callback); err != nil {
		return fmt.Errorf("failed to start TLS profile watcher: %v", err)
	}

	// Wait for context cancellation
	<-ctx.Done()

	// Stop the profile watcher
	if err := s.tlsProfileManager.Stop(); err != nil {
		logger.Errorf("Error stopping TLS profile manager: %v", err)
	}

	logger.Printf("TLS profile watcher stopped")
	return nil
}

// updateTLSConfig is called when the TLS profile changes in OpenShift
func (s *server) updateTLSConfig(newConfig *tls.Config) error {
	logger.Printf("Updating TLS configuration with new config: MinVersion=0x%x, MaxVersion=0x%x, CipherSuites=%d",
		newConfig.MinVersion, newConfig.MaxVersion, len(newConfig.CipherSuites))

	s.tlsConfigMutex.Lock()
	defer s.tlsConfigMutex.Unlock()

	// Preserve the certificates from the current config
	if s.tlsConfig != nil && len(s.tlsConfig.Certificates) > 0 {
		newConfig.Certificates = s.tlsConfig.Certificates
	}

	// Update the stored config - this will be used by GetConfigForClient
	s.tlsConfig = newConfig.Clone()

	logger.Printf("TLS configuration updated successfully")
	return nil
}

// startServer creates and starts a new server with the given listener.
// When the given context is cancelled the server will be shutdown.
// If any errors occur, only the first error will be returned.
func (s *server) startServer(ctx context.Context, listener net.Listener) error {
	srv := &http.Server{Handler: s.handler, ReadHeaderTimeout: time.Minute}
	g, groupCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-groupCtx.Done()

		if err := srv.Shutdown(context.Background()); err != nil {
			return fmt.Errorf("error shutting down server: %v", err)
		}
		return nil
	})

	g.Go(func() error {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("could not start server: %v", err)
		}
		return nil
	})

	return g.Wait()
}

// getNetworkScheme gets the scheme for the HTTP server.
func getNetworkScheme(addr string) string {
	var scheme string
	i := strings.Index(addr, "://")
	if i > -1 {
		scheme = addr[0:i]
	}

	switch scheme {
	case "", "http":
		return "tcp"
	default:
		return scheme
	}
}

// getListenAddress gets the address for the HTTP server.
func getListenAddress(addr string) string {
	slice := strings.SplitN(addr, "//", 2)
	return slice[len(slice)-1]
}

// getCertificate loads the certificate data from the TLS config.
func getCertificate(opts *options.TLS) (tls.Certificate, error) {
	keyData, err := getSecretValue(opts.Key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not load key data: %v", err)
	}

	certData, err := getSecretValue(opts.Cert)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not load cert data: %v", err)
	}

	cert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not parse certificate data: %v", err)
	}

	return cert, nil
}

// getSecretValue wraps util.GetSecretValue so that we can return an error if no
// source is provided.
func getSecretValue(src *options.SecretSource) ([]byte, error) {
	if src == nil {
		return nil, errors.New("no configuration provided")
	}
	return util.GetSecretValue(src)
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by so that dead TCP connections (e.g. closing laptop
// mid-download) eventually go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

// Accept implements the TCPListener interface.
// It sets the keep alive period to 3 minutes for each connection.
func (ln tcpKeepAliveListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	err = tc.SetKeepAlive(true)
	if err != nil {
		logger.Errorf("Error setting Keep-Alive: %v", err)
	}
	err = tc.SetKeepAlivePeriod(3 * time.Minute)
	if err != nil {
		logger.Printf("Error setting Keep-Alive period: %v", err)
	}
	return tc, nil
}
