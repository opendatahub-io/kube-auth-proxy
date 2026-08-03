package k8s

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
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

type tokenCacheEntry struct {
	session   *sessions.SessionState
	expiresAt time.Time
}

// TokenReviewValidator validates Kubernetes service account tokens using the TokenReview API.
// This is independent of the configured provider (OpenShift OAuth, OIDC, etc.)
// and allows service accounts to authenticate alongside human users.
//
// It uses singleflight to deduplicate concurrent TokenReview calls for the same
// token and caches successful results for a short TTL to reduce API server load.
type TokenReviewValidator struct {
	client    kubernetes.Interface
	audiences []string

	sfMu     sync.Mutex
	inflight map[string]*inflightCall

	cacheMu       sync.RWMutex
	cache         map[string]*tokenCacheEntry
	cacheTTL      time.Duration
	reviewTimeout time.Duration
}

type inflightCall struct {
	done chan struct{}
	res  *sessions.SessionState
	err  error
}

// TokenReviewConfig holds optional tuning parameters for the TokenReview validator.
type TokenReviewConfig struct {
	QPS           float32
	Burst         int
	CacheTTL      time.Duration
	ReviewTimeout time.Duration
}

const (
	defaultCacheTTL      = 10 * time.Second
	defaultReviewTimeout = 30 * time.Second
)

// NewTokenReviewValidator creates a new TokenReview validator.
// If kubeconfig is empty, it uses in-cluster configuration.
// The audiences parameter is optional - when empty, tokens are validated against
// the Kubernetes API server's default issuer and audience (default TokenReview behavior).
//
// TLS Configuration:
// Communication with the Kubernetes API server is automatically secured with TLS.
//   - InClusterConfig() loads the cluster CA certificate from /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
//     (automatically mounted by Kubernetes into every pod) and configures the TLS client config.
//   - BuildConfigFromFlags() loads TLS settings from the kubeconfig file, including the cluster CA certificate.
//
// See: https://github.com/kubernetes/client-go/blob/master/rest/config.go
//
// Note: There is a known limitation where client-go does not automatically reload CA certificates during
// cluster CA rotation. Pods may need to be restarted after CA rotation.
// See: https://github.com/kubernetes/kubernetes/issues/119483
func NewTokenReviewValidator(kubeconfig string, audiences []string, cfg *TokenReviewConfig) (*TokenReviewValidator, error) {
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

	if cfg != nil {
		if cfg.QPS > 0 {
			config.QPS = cfg.QPS
		}
		if cfg.Burst > 0 {
			config.Burst = cfg.Burst
		}
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	cacheTTL := defaultCacheTTL
	if cfg != nil && cfg.CacheTTL > 0 {
		cacheTTL = cfg.CacheTTL
	}

	reviewTimeout := defaultReviewTimeout
	if cfg != nil && cfg.ReviewTimeout > 0 {
		reviewTimeout = cfg.ReviewTimeout
	}

	return &TokenReviewValidator{
		client:        client,
		audiences:     audiences,
		inflight:      make(map[string]*inflightCall),
		cache:         make(map[string]*tokenCacheEntry),
		cacheTTL:      cacheTTL,
		reviewTimeout: reviewTimeout,
	}, nil
}

// tokenKey returns a cache-safe hash of the token to avoid holding raw tokens in map keys.
func tokenKey(token string) string {
	h := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", h)
}

// ValidateToken validates a service account token using the Kubernetes TokenReview API.
// It returns a SessionState if the token is valid, or an error if validation fails.
// The TokenReview API is authoritative - it checks with the Kubernetes API server
// whether the token is valid and not expired. If audiences are configured, it also validates
// the token matches the required audiences. When audiences are omitted, the default
// Kubernetes API server issuer and audience validation is used.
//
// Concurrent calls for the same token are deduplicated via singleflight, and
// successful results are cached for a short TTL to reduce API server load.
func (v *TokenReviewValidator) ValidateToken(ctx context.Context, token string) (*sessions.SessionState, error) {
	key := tokenKey(token)

	if v.cacheTTL > 0 {
		v.cacheMu.RLock()
		if entry, ok := v.cache[key]; ok && time.Now().Before(entry.expiresAt) {
			v.cacheMu.RUnlock()
			return copySession(entry.session), nil
		}
		v.cacheMu.RUnlock()
	}

	v.sfMu.Lock()
	if call, ok := v.inflight[key]; ok {
		v.sfMu.Unlock()
		select {
		case <-call.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if call.err != nil {
			return nil, call.err
		}
		return copySession(call.res), nil
	}
	call := &inflightCall{done: make(chan struct{})}
	v.inflight[key] = call
	v.sfMu.Unlock()

	go func() {
		callCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), v.reviewTimeout)
		defer cancel()
		call.res, call.err = v.doTokenReview(callCtx, token)

		if call.err == nil && v.cacheTTL > 0 {
			v.cacheMu.Lock()
			v.sweepExpired()
			v.cache[key] = &tokenCacheEntry{
				session:   call.res,
				expiresAt: time.Now().Add(v.cacheTTL),
			}
			v.cacheMu.Unlock()
		}

		close(call.done)

		v.sfMu.Lock()
		delete(v.inflight, key)
		v.sfMu.Unlock()
	}()

	select {
	case <-call.done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	if call.err != nil {
		return nil, call.err
	}
	return copySession(call.res), nil
}

func (v *TokenReviewValidator) sweepExpired() {
	now := time.Now()
	for key, entry := range v.cache {
		if now.After(entry.expiresAt) {
			delete(v.cache, key)
		}
	}
}

func (v *TokenReviewValidator) doTokenReview(ctx context.Context, token string) (*sessions.SessionState, error) {
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
		if result.Status.Error != "" {
			return nil, fmt.Errorf("token not authenticated by TokenReview API: %s", result.Status.Error)
		}
		return nil, errors.New("token not authenticated by TokenReview API")
	}

	session := &sessions.SessionState{
		User:        result.Status.User.Username,
		Email:       result.Status.User.Username + "@cluster.local",
		Groups:      result.Status.User.Groups,
		AccessToken: token,
	}
	session.CreatedAtNow()
	session.SetExpiresOn(session.Clock.Now().Add(30 * time.Second))

	return session, nil
}

func copySession(s *sessions.SessionState) *sessions.SessionState {
	groups := make([]string, len(s.Groups))
	copy(groups, s.Groups)
	cp := *s
	cp.Groups = groups
	if s.CreatedAt != nil {
		t := *s.CreatedAt
		cp.CreatedAt = &t
	}
	if s.ExpiresOn != nil {
		t := *s.ExpiresOn
		cp.ExpiresOn = &t
	}
	return &cp
}
