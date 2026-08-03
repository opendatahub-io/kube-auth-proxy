package k8s

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	authv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
)

// mockTokenReviewClient wraps a fake clientset and allows us to inject custom behavior
type mockTokenReviewClient struct {
	authv1.AuthenticationV1Interface
	tokenReviewFunc func(ctx context.Context, tr *authenticationv1.TokenReview, opts metav1.CreateOptions) (*authenticationv1.TokenReview, error)
}

func (m *mockTokenReviewClient) TokenReviews() authv1.TokenReviewInterface {
	return &mockTokenReviewInterface{
		tokenReviewFunc: m.tokenReviewFunc,
	}
}

type mockTokenReviewInterface struct {
	authv1.TokenReviewInterface
	tokenReviewFunc func(ctx context.Context, tr *authenticationv1.TokenReview, opts metav1.CreateOptions) (*authenticationv1.TokenReview, error)
}

func (m *mockTokenReviewInterface) Create(ctx context.Context, tr *authenticationv1.TokenReview, opts metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
	return m.tokenReviewFunc(ctx, tr, opts)
}

// mockKubernetesClient wraps fake client with custom TokenReview behavior
type mockKubernetesClient struct {
	kubernetes.Interface
	authClient *mockTokenReviewClient
}

func (m *mockKubernetesClient) AuthenticationV1() authv1.AuthenticationV1Interface {
	return m.authClient
}

func newTestValidator(mockFunc func(ctx context.Context, tr *authenticationv1.TokenReview, opts metav1.CreateOptions) (*authenticationv1.TokenReview, error), audiences []string) *TokenReviewValidator {
	client := &mockKubernetesClient{
		Interface: fake.NewSimpleClientset(),
		authClient: &mockTokenReviewClient{
			tokenReviewFunc: mockFunc,
		},
	}
	return &TokenReviewValidator{
		client:    client,
		audiences: audiences,
		inflight:  make(map[string]*inflightCall),
		cache:     make(map[string]*tokenCacheEntry),
		cacheTTL:  defaultCacheTTL,
	}
}

func TestTokenReviewValidator_ValidateToken_Success(t *testing.T) {
	mockFunc := func(ctx context.Context, tr *authenticationv1.TokenReview, opts metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
		return &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1.UserInfo{
					Username: "system:serviceaccount:test-namespace:test-sa",
					UID:      "abc-123-def",
					Groups:   []string{"system:serviceaccounts", "system:serviceaccounts:test-namespace", "system:authenticated"},
				},
			},
		}, nil
	}

	validator := newTestValidator(mockFunc, []string{"test-audience"})

	session, err := validator.ValidateToken(context.Background(), "valid-token")

	require.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, "system:serviceaccount:test-namespace:test-sa", session.User)
	assert.Equal(t, "system:serviceaccount:test-namespace:test-sa@cluster.local", session.Email)
	assert.Equal(t, "valid-token", session.AccessToken)
	assert.Contains(t, session.Groups, "system:serviceaccounts")
	assert.Contains(t, session.Groups, "system:authenticated")
	assert.True(t, session.ExpiresOn.After(time.Now()))
}

func TestTokenReviewValidator_ValidateToken_InvalidToken(t *testing.T) {
	mockFunc := func(ctx context.Context, tr *authenticationv1.TokenReview, opts metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
		return &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: false,
				Error:         "token is invalid",
			},
		}, nil
	}

	validator := newTestValidator(mockFunc, []string{"test-audience"})

	session, err := validator.ValidateToken(context.Background(), "invalid-token")

	assert.Error(t, err)
	assert.Nil(t, session)
	assert.Contains(t, err.Error(), "token not authenticated")
}

func TestTokenReviewValidator_ValidateToken_ExpiredToken(t *testing.T) {
	mockFunc := func(ctx context.Context, tr *authenticationv1.TokenReview, opts metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
		return &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: false,
				Error:         "token has expired",
			},
		}, nil
	}

	validator := newTestValidator(mockFunc, []string{"test-audience"})

	session, err := validator.ValidateToken(context.Background(), "expired-token")

	assert.Error(t, err)
	assert.Nil(t, session)
	assert.Contains(t, err.Error(), "token not authenticated")
}

func TestTokenReviewValidator_ValidateToken_APIError(t *testing.T) {
	mockFunc := func(ctx context.Context, tr *authenticationv1.TokenReview, opts metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
		return nil, errors.New("connection refused")
	}

	validator := newTestValidator(mockFunc, []string{"test-audience"})

	session, err := validator.ValidateToken(context.Background(), "any-token")

	assert.Error(t, err)
	assert.Nil(t, session)
	assert.Contains(t, err.Error(), "connection refused")
}

func TestTokenReviewValidator_ValidateToken_AudienceValidation(t *testing.T) {
	tests := []struct {
		name              string
		validatorAudience []string
		expectCalled      bool
	}{
		{
			name:              "single audience",
			validatorAudience: []string{"kube-auth-proxy"},
			expectCalled:      true,
		},
		{
			name:              "multiple audiences",
			validatorAudience: []string{"kube-auth-proxy", "other-service"},
			expectCalled:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var receivedAudiences []string
			mockFunc := func(ctx context.Context, tr *authenticationv1.TokenReview, opts metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
				receivedAudiences = tr.Spec.Audiences
				return &authenticationv1.TokenReview{
					Status: authenticationv1.TokenReviewStatus{
						Authenticated: true,
						User: authenticationv1.UserInfo{
							Username: "system:serviceaccount:ns:sa",
							Groups:   []string{"system:authenticated"},
						},
					},
				}, nil
			}

			validator := newTestValidator(mockFunc, tt.validatorAudience)

			_, err := validator.ValidateToken(context.Background(), "test-token")

			require.NoError(t, err)
			assert.Equal(t, tt.validatorAudience, receivedAudiences)
		})
	}
}

func TestTokenReviewValidator_ValidateToken_SessionFields(t *testing.T) {
	mockFunc := func(ctx context.Context, tr *authenticationv1.TokenReview, opts metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
		return &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1.UserInfo{
					Username: "system:serviceaccount:my-namespace:my-sa",
					UID:      "uid-12345",
					Groups:   []string{"group1", "group2", "system:authenticated"},
				},
			},
		}, nil
	}

	validator := newTestValidator(mockFunc, []string{"test-aud"})

	session, err := validator.ValidateToken(context.Background(), "my-token")

	require.NoError(t, err)
	require.NotNil(t, session)

	assert.Equal(t, "system:serviceaccount:my-namespace:my-sa", session.User)
	assert.Equal(t, "system:serviceaccount:my-namespace:my-sa@cluster.local", session.Email)
	assert.Equal(t, "my-token", session.AccessToken)
	assert.Len(t, session.Groups, 3)
	assert.Contains(t, session.Groups, "group1")
	assert.Contains(t, session.Groups, "group2")
	assert.Contains(t, session.Groups, "system:authenticated")

	assert.False(t, session.CreatedAt.IsZero())
	assert.True(t, session.ExpiresOn.After(time.Now()))
	assert.True(t, session.ExpiresOn.Before(time.Now().Add(25*time.Hour)))
}

func TestTokenReviewValidator_Singleflight(t *testing.T) {
	var apiCalls atomic.Int32
	gate := make(chan struct{})

	mockFunc := func(ctx context.Context, tr *authenticationv1.TokenReview, opts metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
		apiCalls.Add(1)
		<-gate
		return &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1.UserInfo{
					Username: "system:serviceaccount:ns:sa",
					Groups:   []string{"system:authenticated"},
				},
			},
		}, nil
	}

	validator := newTestValidator(mockFunc, nil)

	const concurrency = 10
	var wg sync.WaitGroup
	results := make([]*sessions.SessionState, concurrency)
	errs := make([]error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = validator.ValidateToken(context.Background(), "same-token")
		}(i)
	}

	// Let all goroutines start and block on the gate
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()

	assert.Equal(t, int32(1), apiCalls.Load(), "singleflight should deduplicate concurrent calls to 1 API call")

	for i := 0; i < concurrency; i++ {
		require.NoError(t, errs[i])
		assert.Equal(t, "system:serviceaccount:ns:sa", results[i].User)
	}
}

func TestTokenReviewValidator_Cache(t *testing.T) {
	var apiCalls atomic.Int32

	mockFunc := func(ctx context.Context, tr *authenticationv1.TokenReview, opts metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
		apiCalls.Add(1)
		return &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1.UserInfo{
					Username: "system:serviceaccount:ns:sa",
					Groups:   []string{"system:authenticated"},
				},
			},
		}, nil
	}

	validator := newTestValidator(mockFunc, nil)
	validator.cacheTTL = 1 * time.Second

	// First call hits the API
	s1, err := validator.ValidateToken(context.Background(), "cached-token")
	require.NoError(t, err)
	assert.Equal(t, int32(1), apiCalls.Load())

	// Second call should come from cache
	s2, err := validator.ValidateToken(context.Background(), "cached-token")
	require.NoError(t, err)
	assert.Equal(t, int32(1), apiCalls.Load(), "second call should be served from cache")
	assert.Equal(t, s1.User, s2.User)

	// Wait for cache to expire
	time.Sleep(1100 * time.Millisecond)

	// Third call should hit the API again
	_, err = validator.ValidateToken(context.Background(), "cached-token")
	require.NoError(t, err)
	assert.Equal(t, int32(2), apiCalls.Load(), "call after TTL expiry should hit the API")
}

func TestTokenReviewValidator_CacheNotUsedForErrors(t *testing.T) {
	var apiCalls atomic.Int32

	mockFunc := func(ctx context.Context, tr *authenticationv1.TokenReview, opts metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
		apiCalls.Add(1)
		return &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: false,
				Error:         "invalid token",
			},
		}, nil
	}

	validator := newTestValidator(mockFunc, nil)

	_, err := validator.ValidateToken(context.Background(), "bad-token")
	assert.Error(t, err)
	assert.Equal(t, int32(1), apiCalls.Load())

	// Failed validations should not be cached
	_, err = validator.ValidateToken(context.Background(), "bad-token")
	assert.Error(t, err)
	assert.Equal(t, int32(2), apiCalls.Load(), "failed validations should not be cached")
}

func TestTokenReviewValidator_DifferentTokensNotDeduplicated(t *testing.T) {
	var apiCalls atomic.Int32
	gate := make(chan struct{})

	mockFunc := func(ctx context.Context, tr *authenticationv1.TokenReview, opts metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
		apiCalls.Add(1)
		<-gate
		return &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1.UserInfo{
					Username: "system:serviceaccount:ns:sa",
					Groups:   []string{"system:authenticated"},
				},
			},
		}, nil
	}

	validator := newTestValidator(mockFunc, nil)

	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			token := fmt.Sprintf("token-%d", idx)
			_, _ = validator.ValidateToken(context.Background(), token)
		}(i)
	}

	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()

	assert.Equal(t, int32(3), apiCalls.Load(), "different tokens should each produce a separate API call")
}

func TestTokenReviewValidator_SessionCopyIsolation(t *testing.T) {
	mockFunc := func(ctx context.Context, tr *authenticationv1.TokenReview, opts metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
		return &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1.UserInfo{
					Username: "system:serviceaccount:ns:sa",
					Groups:   []string{"group1", "group2"},
				},
			},
		}, nil
	}

	validator := newTestValidator(mockFunc, nil)

	s1, err := validator.ValidateToken(context.Background(), "isolation-token")
	require.NoError(t, err)

	// Mutate the returned session's groups
	s1.Groups = append(s1.Groups, "injected-group")

	// Second call should return an unmodified copy from cache
	s2, err := validator.ValidateToken(context.Background(), "isolation-token")
	require.NoError(t, err)
	assert.Len(t, s2.Groups, 2, "cached session should not be affected by mutations to previously returned copies")
}
