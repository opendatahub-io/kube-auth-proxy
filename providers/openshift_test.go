package providers

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOpenShiftProvider(t *testing.T) {
	tests := []struct {
		name                 string
		providerConfig       options.Provider
		expectedProviderName string
		expectedScope        string
	}{
		{
			name: "Default OpenShift provider",
			providerConfig: options.Provider{
				Type: options.OpenShiftProvider,
			},
			expectedProviderName: "OpenShift OAuth",
			expectedScope:        openShiftDefaultScope,
		},
		{
			name: "OpenShift provider with custom scope",
			providerConfig: options.Provider{
				Type:  options.OpenShiftProvider,
				Scope: "user:info",
			},
			expectedProviderName: "OpenShift OAuth",
			expectedScope:        "user:info",
		},
		{
			name: "OpenShift provider with service account auto-detection",
			providerConfig: options.Provider{
				Type:           options.OpenShiftProvider,
				ServiceAccount: "my-service-account",
				// ClientID and ClientSecret intentionally empty to test auto-detection
			},
			expectedProviderName: "OpenShift OAuth",
			expectedScope:        openShiftDefaultScope,
		},
		{
			name: "OpenShift provider with custom display name",
			providerConfig: options.Provider{
				Type: options.OpenShiftProvider,
				Name: "My Custom OpenShift OAuth",
			},
			expectedProviderName: "My Custom OpenShift OAuth",
			expectedScope:        openShiftDefaultScope,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewProvider(tt.providerConfig)
			assert.NoError(t, err)
			assert.NotNil(t, provider)

			// Cast to OpenShiftProvider to access the embedded ProviderData
			openshiftProvider, ok := provider.(*OpenShiftProvider)
			assert.True(t, ok, "Provider should be an OpenShiftProvider")

			assert.Equal(t, tt.expectedProviderName, openshiftProvider.ProviderData.ProviderName)
			assert.Equal(t, tt.expectedScope, openshiftProvider.ProviderData.Scope)
			assert.NotNil(t, openshiftProvider.ValidateURL)
		})
	}
}

func TestOpenShiftProviderGetKubeAPIURLWithPath(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "127.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "123")

	tests := []struct {
		name        string
		path        string
		expectedURL string
	}{
		{
			name:        "User info endpoint",
			path:        "/apis/user.openshift.io/v1/users/~",
			expectedURL: "https://127.0.0.1:123/apis/user.openshift.io/v1/users/~",
		},
		{
			name:        "OAuth discovery endpoint",
			path:        "/.well-known/oauth-authorization-server",
			expectedURL: "https://127.0.0.1:123/.well-known/oauth-authorization-server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getKubeAPIURLWithPath(tt.path)
			assert.Equal(t, tt.expectedURL, result)
		})
	}
}

func TestOpenShiftProviderRedeem(t *testing.T) {
	// Mock OAuth server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify that the request contains the expected parameters
		err := r.ParseForm()
		require.NoError(t, err)

		assert.Equal(t, "authorization_code", r.FormValue("grant_type"))
		assert.Equal(t, "test-code", r.FormValue("code"))
		assert.Equal(t, "test-client-id", r.FormValue("client_id"))
		assert.Equal(t, "test-client-secret", r.FormValue("client_secret"))
		assert.Equal(t, "http://localhost/callback", r.FormValue("redirect_uri"))

		// Check if PKCE code_verifier is present
		codeVerifier := r.FormValue("code_verifier")
		if codeVerifier != "" {
			assert.Equal(t, "test-code-verifier", codeVerifier)
		}

		// Return a successful token response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"access_token": "test-access-token"}`))
	}))
	defer server.Close()

	redeemURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	tests := []struct {
		name         string
		codeVerifier string
		expectedErr  bool
	}{
		{
			name:         "OAuth2 flow without PKCE",
			codeVerifier: "",
			expectedErr:  false,
		},
		{
			name:         "OAuth2 flow with PKCE",
			codeVerifier: "test-code-verifier",
			expectedErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &OpenShiftProvider{
				ProviderData: &ProviderData{
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
					RedeemURL:    redeemURL,
				},
			}

			session, err := provider.Redeem(context.Background(), "http://localhost/callback", "test-code", tt.codeVerifier)

			if tt.expectedErr {
				assert.Error(t, err)
				assert.Nil(t, session)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, session)
				assert.Equal(t, "test-access-token", session.AccessToken)
			}
		})
	}
}

func TestOpenShiftProviderRedeemMissingCode(t *testing.T) {
	provider := &OpenShiftProvider{
		ProviderData: &ProviderData{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		},
	}

	session, err := provider.Redeem(context.Background(), "http://localhost/callback", "", "")
	assert.Error(t, err)
	assert.Nil(t, session)
	assert.Contains(t, err.Error(), "missing code")
}

func TestOpenShiftProviderCacheKeyFormat(t *testing.T) {
	tests := []struct {
		name                string
		useSystemTrustStore bool
		caFiles             []string
		expectedCacheKey    string
	}{
		{
			name:                "System trust store enabled, single CA file",
			useSystemTrustStore: true,
			caFiles:             []string{"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"},
			expectedCacheKey:    "true:/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
		},
		{
			name:                "System trust store disabled, single CA file",
			useSystemTrustStore: false,
			caFiles:             []string{"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"},
			expectedCacheKey:    "false:/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
		},
		{
			name:                "System trust store enabled, multiple CA files",
			useSystemTrustStore: true,
			caFiles:             []string{"/custom/ca1.crt", "/custom/ca2.crt"},
			expectedCacheKey:    "true:/custom/ca1.crt,/custom/ca2.crt",
		},
		{
			name:                "System trust store disabled, multiple CA files",
			useSystemTrustStore: false,
			caFiles:             []string{"/custom/ca1.crt", "/custom/ca2.crt"},
			expectedCacheKey:    "false:/custom/ca1.crt,/custom/ca2.crt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualKey := formatCacheKey(tt.useSystemTrustStore, tt.caFiles)
			assert.Equal(t, tt.expectedCacheKey, actualKey)
		})
	}
}

func TestDiscoverValidateURL(t *testing.T) {
	tests := []struct {
		name      string
		setupEnv  func()
		expectNil bool
	}{
		{
			name: "Valid Kubernetes environment",
			setupEnv: func() {
				t.Setenv("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
				t.Setenv("KUBERNETES_SERVICE_PORT", "443")
			},
			expectNil: false,
		},
		{
			name: "Default Kubernetes environment (uses hardcoded defaults)",
			setupEnv: func() {
				// Test with default environment (empty vars fall back to hardcoded defaults)
			},
			expectNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupEnv()

			result, err := url.Parse(getKubeAPIURLWithPath(openShiftUserInfoPath))
			require.NoError(t, err)

			if tt.expectNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Contains(t, result.String(), "/apis/user.openshift.io/v1/users/~")
				assert.Contains(t, result.String(), "https://")
			}
		})
	}
}

func TestOpenShiftProviderCreateSessionFromToken(t *testing.T) {
	// Mock OpenShift user info API server
	userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that the Authorization header contains the bearer token
		authHeader := r.Header.Get("Authorization")
		assert.True(t, strings.HasPrefix(authHeader, "Bearer "), "Authorization header should start with 'Bearer '")

		token := strings.TrimPrefix(authHeader, "Bearer ")

		switch token {
		case "sha256~valid-token":
			// Return valid user info
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"kind": "User",
				"apiVersion": "user.openshift.io/v1",
				"metadata": {
					"name": "test-user",
					"uid": "12345678-1234-1234-1234-123456789012"
				},
				"identities": ["myidp:test-user"],
				"groups": ["developers", "testers"]
			}`))
		case "sha256~invalid-token":
			// Return 401 Unauthorized for invalid token
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"message": "Unauthorized"}`))
		default:
			// Return 500 for unexpected tokens
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"message": "Internal Server Error"}`))
		}
	}))
	defer userInfoServer.Close()

	// Parse user info URL
	validateURL, err := url.Parse(userInfoServer.URL)
	require.NoError(t, err)

	tests := []struct {
		name        string
		token       string
		expectError bool
		expectUser  string
		expectEmail string
	}{
		{
			name:        "Valid OpenShift OAuth token",
			token:       "sha256~valid-token",
			expectError: false,
			expectUser:  "test-user",
			expectEmail: "",
		},
		{
			name:        "Invalid OpenShift OAuth token",
			token:       "sha256~invalid-token",
			expectError: true,
			expectUser:  "",
			expectEmail: "",
		},
		{
			name:        "Empty token",
			token:       "",
			expectError: true,
			expectUser:  "",
			expectEmail: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &OpenShiftProvider{
				ProviderData: &ProviderData{
					ProviderName: "OpenShift OAuth",
					ValidateURL:  validateURL,
				},
			}

			session, err := provider.CreateSessionFromToken(context.Background(), tt.token)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, session)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, session)
				assert.Equal(t, tt.expectUser, session.User)
				assert.Equal(t, tt.token, session.AccessToken)
				assert.NotNil(t, session.CreatedAt)
				assert.NotNil(t, session.ExpiresOn)
				// Verify that expiration is set to approximately 24 hours from now
				// Allow 1 minute of tolerance for test execution time
				expectedExpiration := session.CreatedAt.Add(24 * 60 * 60 * 1000000000) // 24 hours in nanoseconds
				actualExpiration := *session.ExpiresOn
				diff := actualExpiration.Sub(expectedExpiration)
				assert.True(t, diff < 60*1000000000 && diff > -60*1000000000, "Expiration should be approximately 24 hours from creation")
			}
		})
	}
}

func TestOpenShiftProviderCreateSessionFromTokenWithGroups(t *testing.T) {
	// Mock OpenShift user info API server that returns groups
	userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"kind": "User",
			"apiVersion": "user.openshift.io/v1",
			"metadata": {
				"name": "admin-user",
				"uid": "admin-uid"
			},
			"identities": ["ldap:admin"],
			"groups": ["system:cluster-admins", "developers", "viewers"]
		}`))
	}))
	defer userInfoServer.Close()

	validateURL, err := url.Parse(userInfoServer.URL)
	require.NoError(t, err)

	provider := &OpenShiftProvider{
		ProviderData: &ProviderData{
			ProviderName: "OpenShift OAuth",
			ValidateURL:  validateURL,
		},
	}

	session, err := provider.CreateSessionFromToken(context.Background(), "sha256~admin-token")

	assert.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, "admin-user", session.User)
	assert.Equal(t, "sha256~admin-token", session.AccessToken)
	assert.Contains(t, session.Groups, "system:cluster-admins")
	assert.Contains(t, session.Groups, "developers")
	assert.Contains(t, session.Groups, "viewers")
	assert.Equal(t, 3, len(session.Groups))
}

func TestOpenShiftProviderDiscoveryRetriesAfterFailure(t *testing.T) {
	callCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			callCount++
			if callCount == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte("API server temporarily unavailable"))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"authorization_endpoint": "https://oauth.example.com/authorize",
				"token_endpoint": "https://oauth.example.com/token"
			}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Point the Kubernetes service env vars to our TLS mock server
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	t.Setenv("KUBERNETES_SERVICE_HOST", serverURL.Hostname())
	t.Setenv("KUBERNETES_SERVICE_PORT", serverURL.Port())

	provider := &OpenShiftProvider{
		ProviderData: &ProviderData{},
	}

	// Use the TLS test server's client for discovery (bypass CA validation)
	client := server.Client()

	// First call: discovery fails (503)
	login, redeem, err := provider.discoverOpenShiftOAuth(client)
	assert.Error(t, err, "Discovery should fail on first attempt")
	assert.Nil(t, login)
	assert.Nil(t, redeem)

	// Second call: discovery succeeds (server returns 200)
	login, redeem, err = provider.discoverOpenShiftOAuth(client)
	assert.NoError(t, err, "Discovery should succeed on second attempt")
	assert.NotNil(t, login)
	assert.NotNil(t, redeem)
	assert.Equal(t, "https://oauth.example.com/authorize", login.String())
	assert.Equal(t, "https://oauth.example.com/token", redeem.String())
}

func TestOpenShiftProviderGetLoginURLRetriesAfterFailure(t *testing.T) {
	callCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			callCount++
			if callCount == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte("API server temporarily unavailable"))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"authorization_endpoint": "https://oauth.example.com/authorize",
				"token_endpoint": "https://oauth.example.com/token"
			}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	t.Setenv("KUBERNETES_SERVICE_HOST", serverURL.Hostname())
	t.Setenv("KUBERNETES_SERVICE_PORT", serverURL.Port())

	caFile := writeTestServerCA(t, server)

	provider := &OpenShiftProvider{
		ProviderData: &ProviderData{},
		CAFiles:      []string{caFile},
	}

	// First call: discovery fails (503), GetLoginURL returns empty
	result := provider.GetLoginURL("http://localhost/callback", "state123", "", url.Values{})
	assert.Empty(t, result, "GetLoginURL should return empty when discovery fails")
	assert.Nil(t, provider.LoginURL, "LoginURL should not be set after failure")

	// Second call: discovery succeeds, GetLoginURL returns a valid URL
	result = provider.GetLoginURL("http://localhost/callback", "state123", "", url.Values{})
	assert.NotEmpty(t, result, "GetLoginURL should return a URL after discovery succeeds on retry")
	assert.NotNil(t, provider.LoginURL, "LoginURL should be set after successful discovery")
	assert.Equal(t, "https://oauth.example.com/authorize", provider.LoginURL.String())
	assert.NotNil(t, provider.RedeemURL, "RedeemURL should be set after successful discovery")
	assert.Equal(t, "https://oauth.example.com/token", provider.RedeemURL.String())

	// Third call: should use cached LoginURL (no new discovery call)
	previousCallCount := callCount
	result = provider.GetLoginURL("http://localhost/callback", "state123", "", url.Values{})
	assert.NotEmpty(t, result)
	assert.Equal(t, previousCallCount, callCount, "No additional discovery calls should be made after success")
}

func TestOpenShiftProviderRedeemRetriesDiscoveryAfterFailure(t *testing.T) {
	callCount := 0
	var serverAddr string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			callCount++
			if callCount == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte("API server temporarily unavailable"))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"authorization_endpoint": "` + serverAddr + `/oauth/authorize",
				"token_endpoint": "` + serverAddr + `/oauth/token"
			}`))
		case "/oauth/token":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"access_token": "test-token"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverAddr = server.URL

	parsedURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	t.Setenv("KUBERNETES_SERVICE_HOST", parsedURL.Hostname())
	t.Setenv("KUBERNETES_SERVICE_PORT", parsedURL.Port())

	caFile := writeTestServerCA(t, server)

	provider := &OpenShiftProvider{
		ProviderData: &ProviderData{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		},
		CAFiles: []string{caFile},
	}

	// First call: discovery fails
	_, err = provider.Redeem(context.Background(), "http://localhost/callback", "code123", "")
	assert.Error(t, err, "Redeem should fail when discovery fails")
	assert.Contains(t, err.Error(), "failed to discover redeem URL")

	// Second call: discovery succeeds, token exchange works
	session, err := provider.Redeem(context.Background(), "http://localhost/callback", "code123", "")
	assert.NoError(t, err, "Redeem should succeed after discovery recovers")
	assert.NotNil(t, session)
	assert.Equal(t, "test-token", session.AccessToken)
}

// writeTestServerCA writes the httptest.TLSServer's CA certificate to a temp file
// and returns the file path. The caller should defer os.Remove(path).
func writeTestServerCA(t *testing.T, server *httptest.Server) string {
	t.Helper()
	cert := server.Certificate()
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	f, err := os.CreateTemp(t.TempDir(), "test-ca-*.pem")
	require.NoError(t, err)
	_, err = f.Write(certPEM)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

// Helper function to test cache key formatting
func formatCacheKey(useSystemTrustStore bool, capaths []string) string {
	if useSystemTrustStore {
		return "true:" + strings.Join(capaths, ",")
	}
	return "false:" + strings.Join(capaths, ",")
}
