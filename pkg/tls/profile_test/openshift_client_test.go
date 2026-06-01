package profile_test

import (
	"context"
	"crypto/tls"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	fakeconfigclient "github.com/openshift/client-go/config/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/tls/profile"
)

func TestNewOpenShiftProfileClient(t *testing.T) {
	tests := []struct {
		name        string
		kubeconfig  string
		expectError bool
	}{
		{
			name:        "empty kubeconfig should use in-cluster config",
			kubeconfig:  "",
			expectError: true, // Will fail in test environment without actual cluster
		},
		{
			name:        "invalid kubeconfig path",
			kubeconfig:  "/nonexistent/kubeconfig",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := profile.NewOpenShiftProfileClient(tt.kubeconfig)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, client)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, client)
			assert.False(t, client.IsWatching())
		})
	}
}

func TestOpenShiftProfileClient_FetchTLSProfile(t *testing.T) {
	tests := []struct {
		name        string
		objects     []runtime.Object
		expectError bool
		validate    func(t *testing.T, apiServer *configv1.APIServer)
	}{
		{
			name: "successful fetch of cluster APIServer",
			objects: []runtime.Object{
				&configv1.APIServer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cluster",
					},
					Spec: configv1.APIServerSpec{
						TLSSecurityProfile: &configv1.TLSSecurityProfile{
							Type: configv1.TLSProfileIntermediateType,
						},
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, apiServer *configv1.APIServer) {
				assert.Equal(t, "cluster", apiServer.Name)
				assert.Equal(t, configv1.TLSProfileIntermediateType, apiServer.Spec.TLSSecurityProfile.Type)
			},
		},
		{
			name:        "APIServer not found",
			objects:     []runtime.Object{},
			expectError: true,
		},
		{
			name: "different APIServer name should not affect result",
			objects: []runtime.Object{
				&configv1.APIServer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "other",
					},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := createFakeClient(t, tt.objects)

			ctx := context.Background()
			apiServer, err := client.FetchTLSProfile(ctx)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, apiServer)
			if tt.validate != nil {
				tt.validate(t, apiServer)
			}
		})
	}
}

func TestOpenShiftProfileClient_GetTLSConfig(t *testing.T) {
	tests := []struct {
		name        string
		apiServer   *configv1.APIServer
		expectError bool
		validate    func(t *testing.T, config *tls.Config)
	}{
		{
			name: "intermediate profile",
			apiServer: &configv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.APIServerSpec{
					TLSSecurityProfile: &configv1.TLSSecurityProfile{
						Type: configv1.TLSProfileIntermediateType,
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, config *tls.Config) {
				assert.Equal(t, uint16(tls.VersionTLS12), config.MinVersion)
				assert.Equal(t, uint16(tls.VersionTLS13), config.MaxVersion)
				assert.Equal(t, []string{"http/1.1"}, config.NextProtos)
			},
		},
		{
			name: "modern profile",
			apiServer: &configv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.APIServerSpec{
					TLSSecurityProfile: &configv1.TLSSecurityProfile{
						Type: configv1.TLSProfileModernType,
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, config *tls.Config) {
				assert.Equal(t, uint16(tls.VersionTLS13), config.MinVersion)
				assert.Equal(t, uint16(tls.VersionTLS13), config.MaxVersion)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objects := []runtime.Object{tt.apiServer}
			client := createFakeClient(t, objects)

			ctx := context.Background()
			config, err := client.GetTLSConfig(ctx)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, config)
			if tt.validate != nil {
				tt.validate(t, config)
			}
		})
	}
}

func TestOpenShiftProfileClient_StartWatching(t *testing.T) {
	apiServer := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.APIServerSpec{
			TLSSecurityProfile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileIntermediateType,
			},
		},
	}

	t.Run("start watching successfully", func(t *testing.T) {
		client := createFakeClient(t, []runtime.Object{apiServer})

		callback := func(config *tls.Config) error {
			return nil
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		err := client.StartWatching(ctx, callback)
		assert.NoError(t, err)
		assert.True(t, client.IsWatching())

		// Stop watching
		err = client.Stop()
		assert.NoError(t, err)
		assert.False(t, client.IsWatching())
	})

	t.Run("start watching when already watching should fail", func(t *testing.T) {
		client := createFakeClient(t, []runtime.Object{apiServer})

		callback := func(config *tls.Config) error {
			return nil
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		err := client.StartWatching(ctx, callback)
		require.NoError(t, err)

		// Try to start watching again
		err = client.StartWatching(ctx, callback)
		assert.Error(t, err)
		assert.ErrorIs(t, err, profile.ErrWatcherAlreadyStarted)

		// Cleanup
		err = client.Stop()
		assert.NoError(t, err)
	})

	t.Run("stop when not watching should succeed", func(t *testing.T) {
		client := createFakeClient(t, []runtime.Object{apiServer})

		err := client.Stop()
		assert.NoError(t, err)
		assert.False(t, client.IsWatching())
	})
}

func TestProfileManagerInterface(t *testing.T) {
	// Test that OpenShiftProfileClient implements ProfileManager interface
	var _ profile.Manager = &profile.OpenShiftProfileClient{}
}

// Helper functions

func createFakeClient(t *testing.T, objects []runtime.Object) *profile.OpenShiftProfileClient {
	fakeClient := fakeconfigclient.NewClientset(objects...)
	return profile.NewOpenShiftProfileClientForTesting(fakeClient)
}
