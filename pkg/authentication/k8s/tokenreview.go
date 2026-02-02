package k8s

import (
	"context"
	"errors"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/sessions"
)

// Validator defines the interface for validating Kubernetes service account tokens.
type Validator interface {
	ValidateToken(ctx context.Context, token string) (*sessions.SessionState, error)
}

// TokenReviewValidator validates Kubernetes service account tokens using the TokenReview API.
// This is independent of the configured provider (OpenShift OAuth, OIDC, etc.)
// and allows service accounts to authenticate alongside human users.
type TokenReviewValidator struct {
	client    kubernetes.Interface
	audiences []string
}

// NewTokenReviewValidator creates a new TokenReview validator.
// If kubeconfig is empty, it uses in-cluster configuration.
// The audiences parameter is optional - when empty, tokens are validated against
// the Kubernetes API server's default issuer and audience (default TokenReview behavior).
//
// TLS Configuration:
// Communication with the Kubernetes API server is automatically secured with TLS.
// - InClusterConfig() loads the cluster CA certificate from /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
//   (automatically mounted by Kubernetes into every pod) and configures the TLS client config.
// - BuildConfigFromFlags() loads TLS settings from the kubeconfig file, including the cluster CA certificate.
// See: https://github.com/kubernetes/client-go/blob/master/rest/config.go
//
// Note: There is a known limitation where client-go does not automatically reload CA certificates during
// cluster CA rotation. Pods may need to be restarted after CA rotation.
// See: https://github.com/kubernetes/kubernetes/issues/119483
func NewTokenReviewValidator(kubeconfig string, audiences []string) (*TokenReviewValidator, error) {
	var config *rest.Config
	var err error

	if kubeconfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		config, err = rest.InClusterConfig()
	}

	if err != nil {
		return nil, err
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &TokenReviewValidator{
		client:    client,
		audiences: audiences,
	}, nil
}

// ValidateToken validates a service account token using the Kubernetes TokenReview API.
// It returns a SessionState if the token is valid, or an error if validation fails.
// The TokenReview API is authoritative - it checks with the Kubernetes API server
// whether the token is valid and not expired. If audiences are configured, it also validates
// the token matches the required audiences. When audiences are omitted, the default
// Kubernetes API server issuer and audience validation is used.
func (v *TokenReviewValidator) ValidateToken(ctx context.Context, token string) (*sessions.SessionState, error) {
	tr := &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token:     token,
			Audiences: v.audiences,
		},
	}

	result, err := v.client.AuthenticationV1().TokenReviews().Create(ctx, tr, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	if !result.Status.Authenticated {
		return nil, errors.New("token not authenticated by TokenReview API")
	}

	// Create session from TokenReview response
	// Username format: "system:serviceaccount:namespace:serviceaccount-name"
	session := &sessions.SessionState{
		User:        result.Status.User.Username,
		Email:       result.Status.User.Username + "@cluster.local",
		Groups:      result.Status.User.Groups,
		AccessToken: token,
	}
	session.CreatedAtNow()

	// Service account tokens can have expiration, but we set a short session expiry
	// since this is a single request session. The actual token expiration is enforced
	// by the TokenReview API on each request.
	session.SetExpiresOn(time.Now().Add(30 * time.Second))

	return session, nil
}
