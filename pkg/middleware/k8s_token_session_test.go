package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	middlewareapi "github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/middleware"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTokenReviewValidator is a test double for TokenReviewValidator
type mockTokenReviewValidator struct {
	validateFunc func(ctx context.Context, token string) (*sessions.SessionState, error)
}

func (m *mockTokenReviewValidator) ValidateToken(ctx context.Context, token string) (*sessions.SessionState, error) {
	if m.validateFunc != nil {
		return m.validateFunc(ctx, token)
	}
	return nil, errors.New("not implemented")
}

func TestK8sTokenSessionLoader_ValidToken(t *testing.T) {
	// Mock successful validation
	validator := &mockTokenReviewValidator{
		validateFunc: func(ctx context.Context, token string) (*sessions.SessionState, error) {
			assert.Equal(t, "test-valid-token", token)
			return &sessions.SessionState{
				User:   "system:serviceaccount:ns:sa",
				Email:  "system:serviceaccount:ns:sa@cluster.local",
				Groups: []string{"system:authenticated"},
			}, nil
		},
	}

	loader := NewK8sTokenSessionLoader(validator)
	handler := loader(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify session was set
		scope := middlewareapi.GetRequestScope(r)
		require.NotNil(t, scope)
		require.NotNil(t, scope.Session)
		assert.Equal(t, "system:serviceaccount:ns:sa", scope.Session.User)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer test-valid-token")

	// Set up scope
	scope := &middlewareapi.RequestScope{}
	req = middlewareapi.AddRequestScope(req, scope)

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusOK, rw.Code)
}

func TestK8sTokenSessionLoader_InvalidToken(t *testing.T) {
	// Mock failed validation
	validator := &mockTokenReviewValidator{
		validateFunc: func(ctx context.Context, token string) (*sessions.SessionState, error) {
			return nil, errors.New("token not authenticated")
		},
	}

	nextHandlerCalled := false
	loader := NewK8sTokenSessionLoader(validator)
	handler := loader(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextHandlerCalled = true
		// Verify session was NOT set
		scope := middlewareapi.GetRequestScope(r)
		require.NotNil(t, scope)
		assert.Nil(t, scope.Session)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	scope := &middlewareapi.RequestScope{}
	req = middlewareapi.AddRequestScope(req, scope)

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	assert.True(t, nextHandlerCalled, "Next handler should be called even when validation fails")
	assert.Equal(t, http.StatusOK, rw.Code)
}

func TestK8sTokenSessionLoader_NoAuthHeader(t *testing.T) {
	validator := &mockTokenReviewValidator{
		validateFunc: func(ctx context.Context, token string) (*sessions.SessionState, error) {
			t.Fatal("ValidateToken should not be called when no auth header present")
			return nil, nil
		},
	}

	nextHandlerCalled := false
	loader := NewK8sTokenSessionLoader(validator)
	handler := loader(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextHandlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	// No Authorization header

	scope := &middlewareapi.RequestScope{}
	req = middlewareapi.AddRequestScope(req, scope)

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	assert.True(t, nextHandlerCalled)
	assert.Equal(t, http.StatusOK, rw.Code)
}

func TestK8sTokenSessionLoader_NonBearerAuth(t *testing.T) {
	validator := &mockTokenReviewValidator{
		validateFunc: func(ctx context.Context, token string) (*sessions.SessionState, error) {
			t.Fatal("ValidateToken should not be called for non-Bearer auth")
			return nil, nil
		},
	}

	nextHandlerCalled := false
	loader := NewK8sTokenSessionLoader(validator)
	handler := loader(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextHandlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz") // Basic auth

	scope := &middlewareapi.RequestScope{}
	req = middlewareapi.AddRequestScope(req, scope)

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	assert.True(t, nextHandlerCalled)
	assert.Equal(t, http.StatusOK, rw.Code)
}

func TestK8sTokenSessionLoader_SessionAlreadyLoaded(t *testing.T) {
	validator := &mockTokenReviewValidator{
		validateFunc: func(ctx context.Context, token string) (*sessions.SessionState, error) {
			t.Fatal("ValidateToken should not be called when session already exists")
			return nil, nil
		},
	}

	existingSession := &sessions.SessionState{
		User:  "existing-user",
		Email: "existing@example.com",
	}

	nextHandlerCalled := false
	loader := NewK8sTokenSessionLoader(validator)
	handler := loader(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextHandlerCalled = true
		scope := middlewareapi.GetRequestScope(r)
		require.NotNil(t, scope)
		require.NotNil(t, scope.Session)
		assert.Equal(t, "existing-user", scope.Session.User)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer some-token")

	scope := &middlewareapi.RequestScope{
		Session: existingSession,
	}
	req = middlewareapi.AddRequestScope(req, scope)

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	assert.True(t, nextHandlerCalled)
	assert.Equal(t, http.StatusOK, rw.Code)
}

func TestK8sTokenSessionLoader_NilScope(t *testing.T) {
	validator := &mockTokenReviewValidator{}

	loader := NewK8sTokenSessionLoader(validator)
	handler := loader(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Next handler should not be called when scope is nil")
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	// Do NOT add request scope - this simulates misconfigured middleware

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusInternalServerError, rw.Code)
	assert.Contains(t, rw.Body.String(), "Internal Server Error")
}

func TestK8sTokenSessionLoader_TokenExtraction(t *testing.T) {
	tests := []struct {
		name           string
		authHeader     string
		expectedToken  string
		shouldValidate bool
	}{
		{
			name:           "Bearer with token",
			authHeader:     "Bearer my-token-123",
			expectedToken:  "my-token-123",
			shouldValidate: true,
		},
		{
			name:           "Bearer with long token",
			authHeader:     "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMyJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50In0.signature",
			expectedToken:  "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMyJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50In0.signature",
			shouldValidate: true,
		},
		{
			name:           "Bearer with spaces in token (edge case)",
			authHeader:     "Bearer token with spaces",
			expectedToken:  "token with spaces",
			shouldValidate: true,
		},
		{
			name:           "No Bearer prefix",
			authHeader:     "my-token",
			shouldValidate: false,
		},
		{
			name:           "Basic auth",
			authHeader:     "Basic dXNlcjpwYXNz",
			shouldValidate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var receivedToken string
			validated := false

			validator := &mockTokenReviewValidator{
				validateFunc: func(ctx context.Context, token string) (*sessions.SessionState, error) {
					validated = true
					receivedToken = token
					return &sessions.SessionState{
						User: "test-user",
					}, nil
				},
			}

			loader := NewK8sTokenSessionLoader(validator)
			handler := loader(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", tt.authHeader)

			scope := &middlewareapi.RequestScope{}
			req = middlewareapi.AddRequestScope(req, scope)

			rw := httptest.NewRecorder()
			handler.ServeHTTP(rw, req)

			if tt.shouldValidate {
				assert.True(t, validated, "Token should be validated")
				assert.Equal(t, tt.expectedToken, receivedToken)
			} else {
				assert.False(t, validated, "Token should not be validated")
			}
		})
	}
}

func TestK8sTokenSessionLoader_APIError(t *testing.T) {
	// Simulate API server being down
	validator := &mockTokenReviewValidator{
		validateFunc: func(ctx context.Context, token string) (*sessions.SessionState, error) {
			return nil, errors.New("connection refused: dial tcp 10.0.0.1:6443: connect: connection refused")
		},
	}

	nextHandlerCalled := false
	loader := NewK8sTokenSessionLoader(validator)
	handler := loader(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextHandlerCalled = true
		// Session should not be set
		scope := middlewareapi.GetRequestScope(r)
		require.NotNil(t, scope)
		assert.Nil(t, scope.Session)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer test-token")

	scope := &middlewareapi.RequestScope{}
	req = middlewareapi.AddRequestScope(req, scope)

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	// Should pass to next handler (OIDC/OAuth can try)
	assert.True(t, nextHandlerCalled)
	assert.Equal(t, http.StatusOK, rw.Code)
}
