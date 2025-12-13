package providers

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bitly/go-simplejson"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/options"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/sessions"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/logger"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/util"
)

const (
	// openShiftDefaultScope defines the default OAuth scopes for OpenShift authentication
	// user:info - allows reading user information
	openShiftDefaultScope = "user:info"

	// Default OpenShift provider name
	openShiftDefaultName = "OpenShift OAuth"

	// OpenShift API paths
	openShiftUserInfoPath       = "/apis/user.openshift.io/v1/users/~"
	openShiftOAuthDiscoveryPath = "/.well-known/oauth-authorization-server"
)

// OpenShiftProvider implements OAuth2 authentication for OpenShift clusters.
// It supports both manual configuration and automatic service account detection
// when running inside an OpenShift/Kubernetes cluster.
type OpenShiftProvider struct {
	*ProviderData
	useSystemTrustStore bool
	discoveryOnce       sync.Once
	discoveryErr        error
	discoveredLogin     *url.URL
	discoveredRedeem    *url.URL

	// CAFiles contains paths to custom CA certificate files for TLS connections
	// to the OpenShift OAuth server and API endpoints
	CAFiles []string

	// httpClientCache caches HTTP clients by CA configuration to avoid
	// recreating clients when CA certificates haven't changed
	httpClientCache sync.Map
}

// NewOpenShiftProvider creates a new OpenShiftProvider instance.
// It configures default OAuth endpoints and handles service account auto-detection
// if the ServiceAccount option is specified.
func NewOpenShiftProvider(p *ProviderData, cfg options.Provider) (*OpenShiftProvider, error) {
	// Determine provider display name
	name := openShiftDefaultName
	if p.ProviderName != "" {
		name = p.ProviderName
	}

	scope := openShiftDefaultScope
	if p.Scope != "" {
		scope = p.Scope
	}

	// Set provider defaults
	defaults := providerDefaults{
		name:        name,
		scope:       scope,
		loginURL:    nil,
		redeemURL:   nil,
		validateURL: nil,
	}

	// Set default validateURL if not already configured
	if p.ValidateURL == nil || p.ValidateURL.String() == "" {
		discoveredURL, err := url.Parse(util.GetKubernetesAPIURL(openShiftUserInfoPath))
		if err != nil {
			return nil, fmt.Errorf("failed to auto-detect validate URL: %v", err)
		}
		defaults.validateURL = discoveredURL
	}

	p.setProviderDefaults(defaults)

	// Auto-detect service account credentials if service account is specified
	// and no explicit credentials are provided
	if cfg.ServiceAccount != "" && p.ClientID == "" && p.ClientSecret == "" {
		clientID, clientSecret := loadServiceAccountDefaults(cfg.ServiceAccount, p.ClientSecretFile)
		if clientID != "" {
			p.ClientID = clientID
		}
		if clientSecret != "" {
			p.ClientSecret = clientSecret
		}
	}

	// Use Bearer token for API calls
	p.getAuthorizationHeaderFunc = makeOIDCHeader

	return &OpenShiftProvider{
		ProviderData:        p,
		CAFiles:             cfg.CAFiles,
		useSystemTrustStore: cfg.UseSystemTrustStore,
	}, nil
}

// GetLoginURL returns the OAuth login URL, using discovery if not configured
func (p *OpenShiftProvider) GetLoginURL(redirectURI, state, _ string, extraParams url.Values) string {
	// If LoginURL is not configured, try auto-discovery as a convenience
	if p.LoginURL == nil || p.LoginURL.String() == "" {
		logger.Printf("LoginURL not configured, attempting auto-discovery from Kubernetes API")
		client, err := p.newOpenShiftClient()
		if err != nil {
			logger.Errorf("Failed to create OpenShift client for discovery: %v", err)
			logger.Printf("Please configure --login-url manually")
			return ""
		}
		p.discoveryOnce.Do(func() {
			p.discoveredLogin, p.discoveredRedeem, p.discoveryErr = p.discoverOpenShiftOAuth(client)
		})
		if p.discoveryErr != nil || p.discoveredLogin == nil {
			if p.discoveryErr != nil {
				logger.Errorf("Failed to discover OpenShift OAuth endpoints: %v", p.discoveryErr)
			}
			logger.Printf("Please configure --login-url and --redeem-url manually")
			return ""
		}
		p.LoginURL = p.discoveredLogin
		if p.RedeemURL == nil || p.RedeemURL.String() == "" {
			p.RedeemURL = p.discoveredRedeem
		}
		logger.Printf("Auto-discovered LoginURL: %s", p.LoginURL.String())
		if p.RedeemURL != nil {
			logger.Printf("Auto-discovered RedeemURL: %s", p.RedeemURL.String())
		}
	}

	// Build the complete OAuth2 authorization URL using the standard helper
	loginURL := makeLoginURL(p.Data(), redirectURI, state, extraParams)
	return loginURL.String()
}

// Redeem exchanges the authorization code for an access token
func (p *OpenShiftProvider) Redeem(ctx context.Context, redirectURL, code, codeVerifier string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, errors.New("missing code")
	}

	client, err := p.newOpenShiftClient()
	if err != nil {
		return nil, err
	}

	// Get redeem URL from discovery if not configured
	redeemURL := p.RedeemURL
	if redeemURL == nil || redeemURL.String() == "" {
		p.discoveryOnce.Do(func() {
			p.discoveredLogin, p.discoveredRedeem, p.discoveryErr = p.discoverOpenShiftOAuth(client)
		})
		if p.discoveryErr != nil || p.discoveredRedeem == nil {
			return nil, fmt.Errorf("failed to discover redeem URL: %v", p.discoveryErr)
		}
		redeemURL = p.discoveredRedeem
		// Persist for subsequent calls if not explicitly configured
		if p.RedeemURL == nil || p.RedeemURL.String() == "" {
			p.RedeemURL = redeemURL
		}
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if codeVerifier != "" {
		params.Add("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", redeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("token endpoint %q returned status %d", redeemURL.String(), resp.StatusCode)
	}

	// Try JSON response first
	var jsonResponse struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &jsonResponse); err == nil && jsonResponse.AccessToken != "" {
		return &sessions.SessionState{
			AccessToken: jsonResponse.AccessToken,
		}, nil
	}

	// Try form-encoded response
	v, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	if accessToken := v.Get("access_token"); accessToken != "" {
		return &sessions.SessionState{
			AccessToken: accessToken,
		}, nil
	}

	return nil, fmt.Errorf("no access token found %s", body)
}

// EnrichSession enriches the session with user information from OpenShift
func (p *OpenShiftProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	client, err := p.newOpenShiftClient()
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", p.ValidateURL.String(), nil)
	if err != nil {
		return fmt.Errorf("unable to build request to get user info: %v", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.AccessToken))

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("unable to retrieve user information: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("got %d %s", resp.StatusCode, body)
	}

	data, err := simplejson.NewJson(body)
	if err != nil {
		return err
	}

	// Extract user information
	var userResp struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Email  string   `json:"email"`
		Groups []string `json:"groups"`
	}

	if err := json.Unmarshal(body, &userResp); err != nil {
		return fmt.Errorf("unable to parse user information: %v", err)
	}

	name := strings.TrimSpace(userResp.Metadata.Name)
	if name == "" {
		// Fallback to extracting from JSON
		name, err = data.Get("metadata").Get("name").String()
		if err != nil {
			return fmt.Errorf("user information has no name field: %v", err)
		}
	}

	s.User = name

	// Set email using switch for better readability
	switch {
	case userResp.Email != "":
		s.Email = userResp.Email
	case strings.Contains(name, "@"):
		s.Email = name
	default:
		// Default cluster-local email
		s.Email = name + "@cluster.local"
	}

	// Extract groups if present
	if len(userResp.Groups) > 0 {
		s.Groups = userResp.Groups
	}

	return nil
}

// CreateSessionFromToken converts OpenShift OAuth bearer tokens into sessions
// This enables CLI access using `oc whoami -t` tokens with Authorization: Bearer header
func (p *OpenShiftProvider) CreateSessionFromToken(ctx context.Context, token string) (*sessions.SessionState, error) {
	if token == "" {
		return nil, errors.New("empty token provided")
	}

	// Create a session with the provided token
	session := &sessions.SessionState{
		AccessToken: token,
	}

	// Validate the token and enrich session with user information
	// by calling the OpenShift user info endpoint
	err := p.EnrichSession(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("failed to validate token and get user info: %v", err)
	}

	// Set session creation time and expiration
	session.CreatedAtNow()
	// OpenShift tokens typically don't have expiration in the token itself,
	// but we can set a reasonable session lifetime (e.g., 24 hours)
	// The token will be validated on each request anyway via ValidateSession
	session.SetExpiresOn(time.Now().Add(24 * time.Hour))

	return session, nil
}

// ValidateSession validates the session by checking the user endpoint
// This method overrides the default validateToken to use our custom HTTP client
// with proper CA certificate configuration for OpenShift API calls.
func (p *OpenShiftProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	if s.AccessToken == "" || p.ValidateURL == nil || p.ValidateURL.String() == "" {
		return false
	}

	// Use our custom HTTP client with CA certificates
	client, err := p.newOpenShiftClient()
	if err != nil {
		logger.Errorf("failed to create OpenShift client: %v", err)
		return false
	}

	// Create request to validate token
	req, err := http.NewRequestWithContext(ctx, "GET", p.ValidateURL.String(), nil)
	if err != nil {
		logger.Errorf("failed to create validation request: %v", err)
		return false
	}

	// Add authorization header
	header := makeOIDCHeader(s.AccessToken)
	for key, values := range header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// Perform the request
	resp, err := client.Do(req)
	if err != nil {
		logger.Errorf("token validation request failed: %v", err)
		return false
	}
	defer resp.Body.Close()

	// Read response body for logging
	body, _ := io.ReadAll(resp.Body)
	logger.Printf("%d GET %s %s", resp.StatusCode, p.ValidateURL.String(), string(body))

	if resp.StatusCode == 200 {
		return true
	}
	logger.Errorf("token validation request failed: status %d - %s", resp.StatusCode, string(body))
	return false
}

// newOpenShiftClient returns a client for connecting to the OpenShift OAuth server
func (p *OpenShiftProvider) newOpenShiftClient() (*http.Client, error) {
	capaths := p.CAFiles
	if len(capaths) == 0 {
		capaths = []string{util.ServiceAccountCAPath}
	}

	// Check if DefaultTransport has InsecureSkipVerify set (from --ssl-insecure-skip-verify flag)
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	insecureSkipVerify := false
	if ok && defaultTransport.TLSClientConfig != nil {
		insecureSkipVerify = defaultTransport.TLSClientConfig.InsecureSkipVerify
	}

	// Simple cache key based on CA paths, system trust store, and insecure skip verify settings
	cacheKey := fmt.Sprintf("%t:%t:%s", p.useSystemTrustStore, insecureSkipVerify, strings.Join(capaths, ","))

	if httpClient, ok := p.httpClientCache.Load(cacheKey); ok {
		return httpClient.(*http.Client), nil
	}

	// Create certificate pool
	var pool *x509.CertPool

	// Load system root CAs if useSystemTrustStore is enabled
	if p.useSystemTrustStore {
		if systemPool, err := x509.SystemCertPool(); err == nil {
			pool = systemPool
		} else {
			pool = x509.NewCertPool()
		}
	} else {
		pool = x509.NewCertPool()
	}

	// Add custom CA certificates
	for _, caPath := range capaths {
		if caPEM, err := os.ReadFile(caPath); err == nil {
			if ok := pool.AppendCertsFromPEM(caPEM); !ok {
				logger.Errorf("no certs appended from CA file %s", caPath)
			}
		} else {
			logger.Errorf("could not load CA file %s: %v", caPath, err)
		}
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
				// Use strong security settings
				MinVersion: tls.VersionTLS12,
				// #nosec G402 -- InsecureSkipVerify is a configurable option we allow (from --ssl-insecure-skip-verify)
				InsecureSkipVerify: insecureSkipVerify,
			},
		},
		Timeout: 1 * time.Minute,
	}
	p.httpClientCache.Store(cacheKey, httpClient)

	return httpClient, nil
}

// discoverOpenShiftOAuth discovers OAuth endpoints from the well-known endpoint
func (p *OpenShiftProvider) discoverOpenShiftOAuth(client *http.Client) (*url.URL, *url.URL, error) {
	wellKnownURL := util.GetKubernetesAPIURL(openShiftOAuthDiscoveryPath)
	logger.Printf("Performing OAuth discovery against %s", wellKnownURL)

	req, err := http.NewRequest("GET", wellKnownURL, nil)
	if err != nil {
		return nil, nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("got %d %s", resp.StatusCode, body)
	}

	data, err := simplejson.NewJson(body)
	if err != nil {
		return nil, nil, err
	}

	var loginURL, redeemURL *url.URL
	if value, err := data.Get("authorization_endpoint").String(); err == nil && len(value) > 0 {
		if loginURL, err = url.Parse(value); err != nil {
			return nil, nil, fmt.Errorf("unable to parse 'authorization_endpoint' from %s: %v", wellKnownURL, err)
		}
	} else {
		return nil, nil, fmt.Errorf("no 'authorization_endpoint' provided by %s: %v", wellKnownURL, err)
	}

	if value, err := data.Get("token_endpoint").String(); err == nil && len(value) > 0 {
		if redeemURL, err = url.Parse(value); err != nil {
			return nil, nil, fmt.Errorf("unable to parse 'token_endpoint' from %s: %v", wellKnownURL, err)
		}
	} else {
		return nil, nil, fmt.Errorf("no 'token_endpoint' provided by %s: %v", wellKnownURL, err)
	}

	return loginURL, redeemURL, nil
}

// loadServiceAccountDefaults loads OAuth client defaults from the mounted service account.
// This function reads the service account namespace and token files that are automatically
// mounted by Kubernetes when the proxy runs as a pod.
// If clientSecretFile is provided, it uses that path instead of the default service account token path.
func loadServiceAccountDefaults(serviceAccount, clientSecretFile string) (clientID, clientSecret string) {
	if serviceAccount == "" {
		return "", ""
	}

	// Read namespace from mounted service account
	if data, err := os.ReadFile(util.ServiceAccountNamespacePath); err == nil && len(data) > 0 {
		namespace := strings.TrimSpace(string(data))
		clientID = fmt.Sprintf("system:serviceaccount:%s:%s", namespace, serviceAccount)
		logger.Printf("Auto-detected client-id from service account: %s", clientID)
	}

	// Determine which token file to use
	tokenPath := util.ServiceAccountTokenPath
	if clientSecretFile != "" {
		tokenPath = clientSecretFile
		logger.Printf("Using custom client-secret-file: %s", tokenPath)
	} else {
		logger.Printf("Using default service account token: %s", tokenPath)
	}

	// Read token from the determined path
	if data, err := os.ReadFile(tokenPath); err == nil && len(data) > 0 {
		clientSecret = strings.TrimSpace(string(data))
		logger.Printf("Auto-detected client-secret from: %s", tokenPath)
	} else {
		logger.Errorf("Failed to read client secret from %s: %v", tokenPath, err)
	}

	return clientID, clientSecret
}
