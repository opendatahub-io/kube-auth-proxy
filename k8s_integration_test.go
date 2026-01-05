package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/sessions"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/validation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockK8sTokenValidator is a test double for k8s.Validator interface
type mockK8sTokenValidator struct {
	validateFunc func(ctx context.Context, token string) (*sessions.SessionState, error)
}

func (m *mockK8sTokenValidator) ValidateToken(ctx context.Context, token string) (*sessions.SessionState, error) {
	if m.validateFunc != nil {
		return m.validateFunc(ctx, token)
	}
	return nil, fmt.Errorf("not implemented")
}

func TestK8sTokenAuthentication_ValidToken(t *testing.T) {
	opts := baseTestOptions()
	err := validation.Validate(opts)
	require.NoError(t, err)

	validator := &mockK8sTokenValidator{
		validateFunc: func(ctx context.Context, token string) (*sessions.SessionState, error) {
			if token == "valid-k8s-token" {
				sess := &sessions.SessionState{
					User:        "system:serviceaccount:test-ns:test-sa",
					Email:       "system:serviceaccount:test-ns:test-sa@cluster.local",
					Groups:      []string{"system:serviceaccounts", "system:authenticated"},
					AccessToken: token,
				}
				sess.CreatedAtNow()
				return sess, nil
			}
			return nil, fmt.Errorf("invalid token")
		},
	}

	proxy, err := NewOAuthProxy(opts, func(string) bool { return true }, validator)
	require.NoError(t, err)

	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer valid-k8s-token")

	proxy.ServeHTTP(rw, req)

	// Should get past auth (backend will 502 since no upstream)
	assert.NotEqual(t, http.StatusUnauthorized, rw.Code)
	assert.NotEqual(t, http.StatusForbidden, rw.Code)
}

func TestK8sTokenAuthentication_InvalidToken(t *testing.T) {
	opts := baseTestOptions()
	err := validation.Validate(opts)
	require.NoError(t, err)

	validator := &mockK8sTokenValidator{
		validateFunc: func(ctx context.Context, token string) (*sessions.SessionState, error) {
			return nil, fmt.Errorf("token not authenticated by TokenReview API")
		},
	}

	proxy, err := NewOAuthProxy(opts, func(string) bool { return true }, validator)
	require.NoError(t, err)

	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	proxy.ServeHTTP(rw, req)

	// Should redirect to login (no valid session)
	assert.Equal(t, http.StatusFound, rw.Code)
}

func TestK8sTokenAuthentication_NoToken(t *testing.T) {
	opts := baseTestOptions()
	err := validation.Validate(opts)
	require.NoError(t, err)

	validator := &mockK8sTokenValidator{
		validateFunc: func(ctx context.Context, token string) (*sessions.SessionState, error) {
			t.Fatal("Validator should not be called when no token present")
			return nil, nil
		},
	}

	proxy, err := NewOAuthProxy(opts, func(string) bool { return true }, validator)
	require.NoError(t, err)

	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	// No Authorization header

	proxy.ServeHTTP(rw, req)

	// Should redirect to login
	assert.Equal(t, http.StatusFound, rw.Code)
}

func TestK8sTokenAuthentication_NilValidator(t *testing.T) {
	opts := baseTestOptions()
	err := validation.Validate(opts)
	require.NoError(t, err)

	// nil validator means k8s token validation is disabled
	proxy, err := NewOAuthProxy(opts, func(string) bool { return true }, nil)
	require.NoError(t, err)

	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer some-token")

	proxy.ServeHTTP(rw, req)

	// Should fall through to other auth (redirect to login)
	assert.Equal(t, http.StatusFound, rw.Code)
}

func TestK8sTokenAuthentication_FallbackToOIDC(t *testing.T) {
	opts := baseTestOptions()
	opts.SkipJwtBearerTokens = true
	err := validation.Validate(opts)
	require.NoError(t, err)

	k8sValidator := &mockK8sTokenValidator{
		validateFunc: func(ctx context.Context, token string) (*sessions.SessionState, error) {
			// K8s validation fails
			return nil, fmt.Errorf("not a k8s token")
		},
	}

	proxy, err := NewOAuthProxy(opts, func(string) bool { return true }, k8sValidator)
	require.NoError(t, err)

	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer oidc-jwt-token")

	proxy.ServeHTTP(rw, req)

	// K8s validation fails, should fall through to OIDC/OAuth validation
	// In this test setup, that will also fail and redirect
	assert.Equal(t, http.StatusFound, rw.Code)
}

func TestK8sTokenAuthentication_APIServerDown(t *testing.T) {
	opts := baseTestOptions()
	err := validation.Validate(opts)
	require.NoError(t, err)

	validator := &mockK8sTokenValidator{
		validateFunc: func(ctx context.Context, token string) (*sessions.SessionState, error) {
			// Simulate API server unreachable
			return nil, fmt.Errorf("connection refused: dial tcp 10.0.0.1:6443")
		},
	}

	proxy, err := NewOAuthProxy(opts, func(string) bool { return true }, validator)
	require.NoError(t, err)

	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer test-token")

	proxy.ServeHTTP(rw, req)

	// Should fall through to other auth methods (will redirect to login)
	assert.Equal(t, http.StatusFound, rw.Code)
}
