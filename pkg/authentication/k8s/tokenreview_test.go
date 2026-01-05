package k8s

import (
	"context"
	"errors"
	"testing"
	"time"

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

func TestTokenReviewValidator_ValidateToken_Success(t *testing.T) {
	// Mock successful TokenReview response
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

	client := &mockKubernetesClient{
		Interface: fake.NewSimpleClientset(),
		authClient: &mockTokenReviewClient{
			tokenReviewFunc: mockFunc,
		},
	}

	validator := &TokenReviewValidator{
		client:    client,
		audiences: []string{"test-audience"},
	}

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
	// Mock TokenReview response for invalid token
	mockFunc := func(ctx context.Context, tr *authenticationv1.TokenReview, opts metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
		return &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: false,
				Error:         "token is invalid",
			},
		}, nil
	}

	client := &mockKubernetesClient{
		Interface: fake.NewSimpleClientset(),
		authClient: &mockTokenReviewClient{
			tokenReviewFunc: mockFunc,
		},
	}

	validator := &TokenReviewValidator{
		client:    client,
		audiences: []string{"test-audience"},
	}

	session, err := validator.ValidateToken(context.Background(), "invalid-token")

	assert.Error(t, err)
	assert.Nil(t, session)
	assert.Contains(t, err.Error(), "token not authenticated")
}

func TestTokenReviewValidator_ValidateToken_ExpiredToken(t *testing.T) {
	// Mock TokenReview response for expired token
	mockFunc := func(ctx context.Context, tr *authenticationv1.TokenReview, opts metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
		return &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: false,
				Error:         "token has expired",
			},
		}, nil
	}

	client := &mockKubernetesClient{
		Interface: fake.NewSimpleClientset(),
		authClient: &mockTokenReviewClient{
			tokenReviewFunc: mockFunc,
		},
	}

	validator := &TokenReviewValidator{
		client:    client,
		audiences: []string{"test-audience"},
	}

	session, err := validator.ValidateToken(context.Background(), "expired-token")

	assert.Error(t, err)
	assert.Nil(t, session)
	assert.Contains(t, err.Error(), "token not authenticated")
}

func TestTokenReviewValidator_ValidateToken_APIError(t *testing.T) {
	// Mock API error
	mockFunc := func(ctx context.Context, tr *authenticationv1.TokenReview, opts metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
		return nil, errors.New("connection refused")
	}

	client := &mockKubernetesClient{
		Interface: fake.NewSimpleClientset(),
		authClient: &mockTokenReviewClient{
			tokenReviewFunc: mockFunc,
		},
	}

	validator := &TokenReviewValidator{
		client:    client,
		audiences: []string{"test-audience"},
	}

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

			client := &mockKubernetesClient{
				Interface: fake.NewSimpleClientset(),
				authClient: &mockTokenReviewClient{
					tokenReviewFunc: mockFunc,
				},
			}

			validator := &TokenReviewValidator{
				client:    client,
				audiences: tt.validatorAudience,
			}

			_, err := validator.ValidateToken(context.Background(), "test-token")

			require.NoError(t, err)
			assert.Equal(t, tt.validatorAudience, receivedAudiences)
		})
	}
}

func TestTokenReviewValidator_ValidateToken_SessionFields(t *testing.T) {
	// Test that all session fields are populated correctly
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

	client := &mockKubernetesClient{
		Interface: fake.NewSimpleClientset(),
		authClient: &mockTokenReviewClient{
			tokenReviewFunc: mockFunc,
		},
	}

	validator := &TokenReviewValidator{
		client:    client,
		audiences: []string{"test-aud"},
	}

	session, err := validator.ValidateToken(context.Background(), "my-token")

	require.NoError(t, err)
	require.NotNil(t, session)

	// Verify all fields
	assert.Equal(t, "system:serviceaccount:my-namespace:my-sa", session.User)
	assert.Equal(t, "system:serviceaccount:my-namespace:my-sa@cluster.local", session.Email)
	assert.Equal(t, "my-token", session.AccessToken)
	assert.Len(t, session.Groups, 3)
	assert.Contains(t, session.Groups, "group1")
	assert.Contains(t, session.Groups, "group2")
	assert.Contains(t, session.Groups, "system:authenticated")

	// Verify timestamps
	assert.False(t, session.CreatedAt.IsZero())
	assert.True(t, session.ExpiresOn.After(time.Now()))
	assert.True(t, session.ExpiresOn.Before(time.Now().Add(25*time.Hour)))
}
