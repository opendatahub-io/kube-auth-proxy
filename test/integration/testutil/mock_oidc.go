package testutil

import (
	"sync"

	"github.com/oauth2-proxy/mockoidc"
)

// MockOIDC wraps mockoidc.MockOIDC with a simpler test API.
type MockOIDC struct {
	m           *mockoidc.MockOIDC
	mu          sync.Mutex
	queuedUsers int
}

// NewMockOIDC starts a mock OIDC provider.
func NewMockOIDC() (*MockOIDC, error) {
	m, err := mockoidc.Run()
	if err != nil {
		return nil, err
	}
	return &MockOIDC{m: m}, nil
}

// QueueUser adds a user that will be returned for the next authorization code exchange.
func (m *MockOIDC) QueueUser(email, preferredUsername string, groups []string) {
	m.m.QueueUser(&mockoidc.MockUser{
		Email:             email,
		EmailVerified:     true,
		PreferredUsername: preferredUsername,
		Groups:            groups,
	})
	m.mu.Lock()
	m.queuedUsers++
	m.mu.Unlock()
}

// Issuer returns the OIDC issuer URL.
func (m *MockOIDC) Issuer() string { return m.m.Issuer() }

// ClientID returns the OAuth2 client ID.
func (m *MockOIDC) ClientID() string { return m.m.ClientID }

// ClientSecret returns the OAuth2 client secret.
func (m *MockOIDC) ClientSecret() string { return m.m.ClientSecret }

// QueuedUserCount returns how many users have been queued.
func (m *MockOIDC) QueuedUserCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.queuedUsers
}

// Close shuts down the mock provider.
func (m *MockOIDC) Close() { m.m.Shutdown() } //nolint:errcheck
