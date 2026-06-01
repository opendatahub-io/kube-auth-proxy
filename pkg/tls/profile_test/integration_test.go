package profile_test

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	fakeconfigclient "github.com/openshift/client-go/config/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/tls/profile"
)

// IntegrationTestSuite provides a test suite for integration testing
type IntegrationTestSuite struct {
	suite.Suite
	manager    profile.Manager
	fakeClient *fakeconfigclient.Clientset
}

func TestIntegrationSuite(t *testing.T) {
	// Use fake client for integration tests when no real cluster is available
	suite.Run(t, new(IntegrationTestSuite))
}

func (s *IntegrationTestSuite) SetupTest() {
	// Create a fake client with test APIServer for integration testing
	apiServer := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.APIServerSpec{
			TLSSecurityProfile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileIntermediateType,
			},
		},
	}

	s.fakeClient = fakeconfigclient.NewClientset(apiServer)
	s.manager = profile.NewOpenShiftProfileClientForTesting(s.fakeClient)
}

func (s *IntegrationTestSuite) TearDownTest() {
	if s.manager != nil {
		s.manager.Stop()
	}
}

func (s *IntegrationTestSuite) TestEndToEndProfileFetch() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	config, err := s.manager.GetTLSConfig(ctx)
	s.Require().NoError(err)
	s.Require().NotNil(config)

	// Verify basic TLS config properties
	s.Assert().GreaterOrEqual(config.MinVersion, uint16(tls.VersionTLS12))
	s.Assert().GreaterOrEqual(config.MaxVersion, config.MinVersion)
	s.Assert().Contains(config.NextProtos, "http/1.1")
}

func (s *IntegrationTestSuite) TestProfileChangeDetection() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	callbackCalled := make(chan *tls.Config, 1)
	callback := func(config *tls.Config) error {
		select {
		case callbackCalled <- config:
		default:
			// Channel full, ignore
		}
		return nil
	}

	err := s.manager.StartWatching(ctx, callback)
	s.Require().NoError(err)
	s.Assert().True(s.manager.IsWatching())

	// In a real test, we would modify the cluster APIServer object
	// and verify that the callback is called

	// Wait briefly for initial events
	select {
	case config := <-callbackCalled:
		s.Assert().NotNil(config)
	case <-time.After(5 * time.Second):
		s.T().Fatal("StartWatching never delivered a TLS config update")
	}
}

func (s *IntegrationTestSuite) TestServerTLSUpdate() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Confirm the running manager starts with the Intermediate profile.
	initialConfig, err := s.manager.GetTLSConfig(ctx)
	s.Require().NoError(err)
	s.Require().NotNil(initialConfig)
	s.Assert().Equal(uint16(tls.VersionTLS12), initialConfig.MinVersion)
	s.Assert().Equal(uint16(tls.VersionTLS13), initialConfig.MaxVersion)

	// Register a callback and start the watcher on the *same* manager instance.
	callbackCh := make(chan *tls.Config, 2)
	callback := func(cfg *tls.Config) error {
		select {
		case callbackCh <- cfg:
		default:
		}
		return nil
	}
	s.Require().NoError(s.manager.StartWatching(ctx, callback))

	// Drain the initial informer "add" event so we can isolate the update event below.
	select {
	case <-callbackCh:
	case <-time.After(5 * time.Second):
		s.T().Fatal("timed out waiting for initial informer add event")
	}

	// Mutate the APIServer to Modern profile via the *same* fake client the manager holds.
	modernAPIServer := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.APIServerSpec{
			TLSSecurityProfile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileModernType,
			},
		},
	}
	_, err = s.fakeClient.ConfigV1().APIServers().Update(ctx, modernAPIServer, metav1.UpdateOptions{})
	s.Require().NoError(err)

	// The informer should deliver a MODIFIED event, triggering the update callback.
	var updatedConfig *tls.Config
	select {
	case updatedConfig = <-callbackCh:
	case <-time.After(5 * time.Second):
		s.T().Fatal("timed out waiting for TLS config update callback after APIServer profile change")
	}

	s.Require().NotNil(updatedConfig)
	s.Assert().Equal(uint16(tls.VersionTLS13), updatedConfig.MinVersion)
	s.Assert().Equal(uint16(tls.VersionTLS13), updatedConfig.MaxVersion)
	s.Assert().NotEqual(initialConfig.MinVersion, updatedConfig.MinVersion)
}

func (s *IntegrationTestSuite) TestStartupFailureOnMissingProfile() {
	// Test failure behavior when APIServer is missing
	s.T().Run("missing APIServer object", func(t *testing.T) {
		// Create fake client with no APIServer objects
		emptyFakeClient := fakeconfigclient.NewClientset()
		emptyManager := profile.NewOpenShiftProfileClientForTesting(emptyFakeClient)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Attempt to fetch TLS profile should fail
		_, err := emptyManager.GetTLSConfig(ctx)
		s.Require().Error(err)
		s.Assert().Contains(err.Error(), "failed to fetch TLS profile")
	})

	s.T().Run("APIServer with wrong name", func(t *testing.T) {
		// Create APIServer with wrong name (not "cluster")
		wrongNameAPIServer := &configv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "wrong-name"},
			Spec: configv1.APIServerSpec{
				TLSSecurityProfile: &configv1.TLSSecurityProfile{
					Type: configv1.TLSProfileIntermediateType,
				},
			},
		}

		wrongNameFakeClient := fakeconfigclient.NewClientset(wrongNameAPIServer)
		wrongNameManager := profile.NewOpenShiftProfileClientForTesting(wrongNameFakeClient)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Should fail because APIServer name is not "cluster"
		_, err := wrongNameManager.GetTLSConfig(ctx)
		s.Require().Error(err)
		s.Assert().Contains(err.Error(), "cluster")
	})
}

// Benchmarks for performance testing
func BenchmarkTLSConfigResolution(b *testing.B) {
	apiServer := &configv1.APIServer{
		Spec: configv1.APIServerSpec{
			TLSSecurityProfile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileIntermediateType,
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config, err := profile.ResolveTLSConfig(apiServer)
		if err != nil {
			b.Fatal(err)
		}
		_ = config
	}
}

func BenchmarkCustomProfileResolution(b *testing.B) {
	apiServer := &configv1.APIServer{
		Spec: configv1.APIServerSpec{
			TLSSecurityProfile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: configv1.VersionTLS12,
						Ciphers: []string{
							"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
							"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
							"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
							"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
						},
					},
				},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config, err := profile.ResolveTLSConfig(apiServer)
		if err != nil {
			b.Fatal(err)
		}
		_ = config
	}
}

// Test real-world scenarios
func TestRealWorldScenarios(t *testing.T) {
	t.Run("enterprise security requirements", func(t *testing.T) {
		apiServer := &configv1.APIServer{
			Spec: configv1.APIServerSpec{
				TLSSecurityProfile: &configv1.TLSSecurityProfile{
					Type: configv1.TLSProfileCustomType,
					Custom: &configv1.CustomTLSProfile{
						TLSProfileSpec: configv1.TLSProfileSpec{
							MinTLSVersion: configv1.VersionTLS12,
							Ciphers: []string{
								"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
								"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
								"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
								"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
							},
						},
					},
				},
			},
		}

		config, err := profile.ResolveTLSConfig(apiServer)
		require.NoError(t, err)

		// Verify enterprise security requirements
		assert.GreaterOrEqual(t, config.MinVersion, uint16(tls.VersionTLS12))
		assert.NotEmpty(t, config.CipherSuites)
		assert.Contains(t, config.NextProtos, "http/1.1")

		// Verify no weak cipher suites
		weakCiphers := []uint16{
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		}

		for _, weak := range weakCiphers {
			assert.NotContains(t, config.CipherSuites, weak,
				"Weak cipher suite %x should not be included", weak)
		}
	})

	t.Run("government compliance (FIPS)", func(t *testing.T) {
		// Test FIPS-compliant TLS configuration
		apiServer := &configv1.APIServer{
			Spec: configv1.APIServerSpec{
				TLSSecurityProfile: &configv1.TLSSecurityProfile{
					Type: configv1.TLSProfileCustomType,
					Custom: &configv1.CustomTLSProfile{
						TLSProfileSpec: configv1.TLSProfileSpec{
							MinTLSVersion: configv1.VersionTLS12,
							Ciphers: []string{
								"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
								"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
							},
						},
					},
				},
			},
		}

		config, err := profile.ResolveTLSConfig(apiServer)
		require.NoError(t, err)

		// FIPS requires TLS 1.2+
		assert.GreaterOrEqual(t, config.MinVersion, uint16(tls.VersionTLS12))

		// FIPS-approved cipher suites only
		fipsApprovedCiphers := map[uint16]bool{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: true,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: true,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   true,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   true,
		}

		for _, cipher := range config.CipherSuites {
			assert.True(t, fipsApprovedCiphers[cipher],
				"Cipher suite %x is not FIPS-approved", cipher)
		}
	})

	t.Run("legacy system support", func(t *testing.T) {
		// Test configuration for legacy system compatibility
		apiServer := &configv1.APIServer{
			Spec: configv1.APIServerSpec{
				TLSSecurityProfile: &configv1.TLSSecurityProfile{
					Type: configv1.TLSProfileOldType,
				},
			},
		}

		config, err := profile.ResolveTLSConfig(apiServer)
		require.NoError(t, err)

		// Old profile should support older TLS versions
		assert.Equal(t, uint16(tls.VersionTLS10), config.MinVersion)
		assert.Equal(t, uint16(tls.VersionTLS13), config.MaxVersion)
	})
}
