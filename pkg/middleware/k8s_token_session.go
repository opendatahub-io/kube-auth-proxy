package middleware

import (
	"net/http"
	"strings"

	"github.com/justinas/alice"
	middlewareapi "github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/middleware"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/authentication/k8s"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/logger"
)

// NewK8sTokenSessionLoader creates a session loader middleware that validates
// Kubernetes service account tokens using the TokenReview API.
// This loader is independent of the configured provider (OpenShift OAuth, OIDC, etc.)
// and allows service accounts to authenticate via bearer tokens alongside human users.
func NewK8sTokenSessionLoader(validator *k8s.TokenReviewValidator) alice.Constructor {
	loader := &k8sTokenSessionLoader{
		validator: validator,
	}
	return loader.loadSession
}

// k8sTokenSessionLoader attempts to load sessions from Kubernetes service account tokens
// in Authorization headers. It uses the TokenReview API to validate tokens.
type k8sTokenSessionLoader struct {
	validator *k8s.TokenReviewValidator
}

// loadSession attempts to load a session from a Kubernetes service account token
// in the Authorization header. If no header is found, or if the token is invalid,
// the request is passed to the next handler (which may be OIDC, OAuth, BasicAuth, or cookie-based).
// If a session was already loaded by a previous handler, it will not be replaced.
func (l *k8sTokenSessionLoader) loadSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		scope := middlewareapi.GetRequestScope(req)
		// If scope is nil, this will panic.
		// A scope should always be injected before this handler is called.

		// Skip if session already loaded by previous loader
		if scope.Session != nil {
			next.ServeHTTP(rw, req)
			return
		}

		// Extract Bearer token
		auth := req.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			// No bearer token, pass to next handler
			next.ServeHTTP(rw, req)
			return
		}

		token := strings.TrimPrefix(auth, "Bearer ")

		// Attempt TokenReview validation
		session, err := l.validator.ValidateToken(req.Context(), token)
		if err != nil {
			// TokenReview validation failed
			// Don't return error - this might be an OIDC token or OpenShift OAuth token
			// Let the next handler in the chain try to validate it
			logger.Printf("K8s TokenReview validation failed: %v", err)
			next.ServeHTTP(rw, req)
			return
		}

		// Successfully validated as K8s service account token
		logger.Printf("K8s service account token validated for user: %s", session.User)
		scope.Session = session
		next.ServeHTTP(rw, req)
	})
}
