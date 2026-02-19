package testutil

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"
)

// MockOpenShiftOAuth simulates an OpenShift OAuth + user-info server.
// It implements all 4 endpoints that providers/openshift.go requires:
//   - /.well-known/oauth-authorization-server  (discovery)
//   - /oauth/authorize                          (redirect with code)
//   - /oauth/token                              (code exchange)
//   - /apis/user.openshift.io/v1/users/~        (user info / session validation)
type MockOpenShiftOAuth struct {
	server   *httptest.Server
	username string
	email    string
	groups   []string
	mu       sync.Mutex
	codes    map[string]bool
}

// NewMockOpenShiftOAuth creates and starts a mock OpenShift OAuth server.
// username and email are returned by the user-info endpoint.
func NewMockOpenShiftOAuth(username, email string, groups ...string) *MockOpenShiftOAuth {
	m := &MockOpenShiftOAuth{
		username: username,
		email:    email,
		groups:   groups,
		codes:    make(map[string]bool),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", m.discovery)
	mux.HandleFunc("/oauth/authorize", m.authorize)
	mux.HandleFunc("/oauth/token", m.token)
	mux.HandleFunc("/apis/user.openshift.io/v1/users/~", m.userInfo)
	m.server = httptest.NewServer(mux)
	return m
}

// URL returns the base URL of the mock server.
func (m *MockOpenShiftOAuth) URL() string { return m.server.URL }

// AuthorizeURL returns the full authorize endpoint URL — set as LoginURL in provider options.
func (m *MockOpenShiftOAuth) AuthorizeURL() string { return m.server.URL + "/oauth/authorize" }

// TokenURL returns the full token endpoint URL — set as RedeemURL in provider options.
func (m *MockOpenShiftOAuth) TokenURL() string { return m.server.URL + "/oauth/token" }

// UserInfoURL returns the user-info endpoint URL — set as ValidateURL in provider options.
func (m *MockOpenShiftOAuth) UserInfoURL() string {
	return m.server.URL + "/apis/user.openshift.io/v1/users/~"
}

// Close shuts down the mock server.
func (m *MockOpenShiftOAuth) Close() { m.server.Close() }

func (m *MockOpenShiftOAuth) discovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"issuer":                 m.server.URL,
		"authorization_endpoint": m.AuthorizeURL(),
		"token_endpoint":         m.TokenURL(),
	})
}

func (m *MockOpenShiftOAuth) authorize(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}

	code := fmt.Sprintf("code-%d", time.Now().UnixNano())
	m.mu.Lock()
	m.codes[code] = true
	m.mu.Unlock()

	dest, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := dest.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	dest.RawQuery = q.Encode()
	http.Redirect(w, r, dest.String(), http.StatusFound)
}

func (m *MockOpenShiftOAuth) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	code := r.FormValue("code")
	m.mu.Lock()
	valid := m.codes[code]
	delete(m.codes, code)
	m.mu.Unlock()

	if !valid {
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"access_token": fmt.Sprintf("token-%d", time.Now().UnixNano()),
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}

func (m *MockOpenShiftOAuth) userInfo(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"kind":       "User",
		"apiVersion": "user.openshift.io/v1",
		"metadata": map[string]string{
			"name": m.username,
		},
		"email":  m.email,
		"groups": m.groups,
	})
}
