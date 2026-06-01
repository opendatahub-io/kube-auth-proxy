package profile_test

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/tls/profile"
)

// MockProfileManager is a mock implementation of ProfileManager for testing
type MockProfileManager struct {
	mock.Mock
}

func (m *MockProfileManager) GetTLSConfig(ctx context.Context) (*tls.Config, error) {
	args := m.Called(ctx)
	return args.Get(0).(*tls.Config), args.Error(1)
}

func (m *MockProfileManager) StartWatching(ctx context.Context, callback profile.UpdateCallback) error {
	args := m.Called(ctx, callback)
	return args.Error(0)
}

func (m *MockProfileManager) Stop() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockProfileManager) IsWatching() bool {
	args := m.Called()
	return args.Bool(0)
}

// MockUpdateCallback tracks callback invocations
type MockUpdateCallback struct {
	invocations []callbackInvocation
	mu          sync.Mutex
}

type callbackInvocation struct {
	config *tls.Config
	err    error
}

func (m *MockUpdateCallback) Callback(config *tls.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	err := m.validateConfig(config)
	m.invocations = append(m.invocations, callbackInvocation{
		config: config,
		err:    err,
	})
	return err
}

func (m *MockUpdateCallback) validateConfig(config *tls.Config) error {
	if config == nil {
		return errors.New("config cannot be nil")
	}
	if config.MinVersion > config.MaxVersion {
		return errors.New("invalid TLS version range")
	}
	return nil
}

func (m *MockUpdateCallback) GetInvocations() []callbackInvocation {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]callbackInvocation, len(m.invocations))
	copy(result, m.invocations)
	return result
}

func (m *MockUpdateCallback) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invocations = nil
}

func TestMockProfileManager(t *testing.T) {
	t.Run("successful TLS config retrieval", func(t *testing.T) {
		mockManager := new(MockProfileManager)
		expectedConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
			NextProtos: []string{"http/1.1"},
		}

		mockManager.On("GetTLSConfig", mock.Anything).Return(expectedConfig, nil)

		ctx := context.Background()
		config, err := mockManager.GetTLSConfig(ctx)

		require.NoError(t, err)
		assert.Equal(t, expectedConfig, config)
		mockManager.AssertExpectations(t)
	})

	t.Run("TLS config retrieval error", func(t *testing.T) {
		mockManager := new(MockProfileManager)
		expectedError := errors.New("API server unavailable")

		mockManager.On("GetTLSConfig", mock.Anything).Return((*tls.Config)(nil), expectedError)

		ctx := context.Background()
		config, err := mockManager.GetTLSConfig(ctx)

		assert.Error(t, err)
		assert.Equal(t, expectedError, err)
		assert.Nil(t, config)
		mockManager.AssertExpectations(t)
	})

	t.Run("start watching success", func(t *testing.T) {
		mockManager := new(MockProfileManager)
		mockCallback := &MockUpdateCallback{}

		mockManager.On("StartWatching", mock.Anything, mock.AnythingOfType("profile.UpdateCallback")).Return(nil)
		mockManager.On("IsWatching").Return(true)

		ctx := context.Background()
		err := mockManager.StartWatching(ctx, mockCallback.Callback)

		require.NoError(t, err)
		assert.True(t, mockManager.IsWatching())
		mockManager.AssertExpectations(t)
	})

	t.Run("start watching failure", func(t *testing.T) {
		mockManager := new(MockProfileManager)
		mockCallback := &MockUpdateCallback{}
		expectedError := profile.ErrWatcherAlreadyStarted

		mockManager.On("StartWatching", mock.Anything, mock.AnythingOfType("profile.UpdateCallback")).Return(expectedError)

		ctx := context.Background()
		err := mockManager.StartWatching(ctx, mockCallback.Callback)

		assert.Error(t, err)
		assert.Equal(t, expectedError, err)
		mockManager.AssertExpectations(t)
	})
}

func TestCallbackScenarios(t *testing.T) {
	t.Run("callback receives valid config", func(t *testing.T) {
		mockCallback := &MockUpdateCallback{}
		config := &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
			NextProtos: []string{"http/1.1"},
		}

		err := mockCallback.Callback(config)
		assert.NoError(t, err)

		invocations := mockCallback.GetInvocations()
		require.Len(t, invocations, 1)
		assert.Equal(t, config, invocations[0].config)
		assert.NoError(t, invocations[0].err)
	})

	t.Run("callback receives nil config", func(t *testing.T) {
		mockCallback := &MockUpdateCallback{}

		err := mockCallback.Callback(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "config cannot be nil")

		invocations := mockCallback.GetInvocations()
		require.Len(t, invocations, 1)
		assert.Nil(t, invocations[0].config)
		assert.Error(t, invocations[0].err)
	})

	t.Run("callback receives invalid config", func(t *testing.T) {
		mockCallback := &MockUpdateCallback{}
		invalidConfig := &tls.Config{
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS12, // Invalid: min > max
			NextProtos: []string{"http/1.1"},
		}

		err := mockCallback.Callback(invalidConfig)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid TLS version range")
	})

	t.Run("multiple callback invocations", func(t *testing.T) {
		mockCallback := &MockUpdateCallback{}

		configs := []*tls.Config{
			{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13},
			{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13},
		}

		for _, config := range configs {
			err := mockCallback.Callback(config)
			assert.NoError(t, err)
		}

		invocations := mockCallback.GetInvocations()
		assert.Len(t, invocations, 2)

		for i, invocation := range invocations {
			assert.Equal(t, configs[i], invocation.config)
			assert.NoError(t, invocation.err)
		}
	})
}

func TestErrorHandlingScenarios(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func(*MockProfileManager)
		operation     func(*MockProfileManager) error
		expectedError error
		description   string
	}{
		{
			name: "API server connection timeout",
			setupMock: func(m *MockProfileManager) {
				m.On("GetTLSConfig", mock.Anything).Return((*tls.Config)(nil), context.DeadlineExceeded)
			},
			operation: func(m *MockProfileManager) error {
				ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
				defer cancel()
				_, err := m.GetTLSConfig(ctx)
				return err
			},
			expectedError: context.DeadlineExceeded,
			description:   "should handle API server timeout gracefully",
		},
		{
			name: "API server not found",
			setupMock: func(m *MockProfileManager) {
				m.On("GetTLSConfig", mock.Anything).Return((*tls.Config)(nil), profile.ErrProfileNotFound)
			},
			operation: func(m *MockProfileManager) error {
				ctx := context.Background()
				_, err := m.GetTLSConfig(ctx)
				return err
			},
			expectedError: profile.ErrProfileNotFound,
			description:   "should handle missing TLS profile",
		},
		{
			name: "watcher already started",
			setupMock: func(m *MockProfileManager) {
				m.On("StartWatching", mock.Anything, mock.Anything).Return(profile.ErrWatcherAlreadyStarted)
			},
			operation: func(m *MockProfileManager) error {
				ctx := context.Background()
				callback := func(*tls.Config) error { return nil }
				return m.StartWatching(ctx, callback)
			},
			expectedError: profile.ErrWatcherAlreadyStarted,
			description:   "should prevent starting watcher multiple times",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockManager := new(MockProfileManager)
			tt.setupMock(mockManager)

			err := tt.operation(mockManager)

			assert.Error(t, err, tt.description)
			assert.Equal(t, tt.expectedError, err)
			mockManager.AssertExpectations(t)
		})
	}
}

func TestConcurrentOperations(t *testing.T) {
	t.Run("concurrent GetTLSConfig calls", func(t *testing.T) {
		mockManager := new(MockProfileManager)
		config := &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
			NextProtos: []string{"http/1.1"},
		}

		// Expect multiple calls
		mockManager.On("GetTLSConfig", mock.Anything).Return(config, nil).Times(10)

		var wg sync.WaitGroup
		errors := make(chan error, 10)

		// Start 10 concurrent operations
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx := context.Background()
				_, err := mockManager.GetTLSConfig(ctx)
				errors <- err
			}()
		}

		wg.Wait()
		close(errors)

		// Verify all operations succeeded
		for err := range errors {
			assert.NoError(t, err)
		}

		mockManager.AssertExpectations(t)
	})

	t.Run("concurrent callback invocations", func(t *testing.T) {
		mockCallback := &MockUpdateCallback{}
		config := &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
			NextProtos: []string{"http/1.1"},
		}

		var wg sync.WaitGroup
		concurrency := 5

		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := mockCallback.Callback(config)
				assert.NoError(t, err)
			}()
		}

		wg.Wait()

		invocations := mockCallback.GetInvocations()
		assert.Len(t, invocations, concurrency)

		for _, invocation := range invocations {
			assert.Equal(t, config, invocation.config)
			assert.NoError(t, invocation.err)
		}
	})
}

func TestProfileChangeSimulation(t *testing.T) {
	t.Run("simulate profile changes over time", func(t *testing.T) {
		mockCallback := &MockUpdateCallback{}

		profiles := []struct {
			name   string
			config *tls.Config
		}{
			{
				name: "initial intermediate profile",
				config: &tls.Config{
					MinVersion: tls.VersionTLS12,
					MaxVersion: tls.VersionTLS13,
					NextProtos: []string{"http/1.1"},
				},
			},
			{
				name: "updated to modern profile",
				config: &tls.Config{
					MinVersion: tls.VersionTLS13,
					MaxVersion: tls.VersionTLS13,
					NextProtos: []string{"http/1.1"},
				},
			},
			{
				name: "custom profile with specific ciphers",
				config: &tls.Config{
					MinVersion:   tls.VersionTLS12,
					MaxVersion:   tls.VersionTLS13,
					CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
					NextProtos:   []string{"http/1.1"},
				},
			},
		}

		// Simulate profile changes
		for _, profile := range profiles {
			t.Run(profile.name, func(t *testing.T) {
				err := mockCallback.Callback(profile.config)
				assert.NoError(t, err)
			})
		}

		// Verify all changes were captured
		invocations := mockCallback.GetInvocations()
		require.Len(t, invocations, len(profiles))

		for i, invocation := range invocations {
			assert.Equal(t, profiles[i].config, invocation.config, "Profile %d should match", i)
			assert.NoError(t, invocation.err, "Profile %d should not have errors", i)
		}
	})
}
