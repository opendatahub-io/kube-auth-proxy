package profile_test

import (
	"crypto/tls"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/tls/profile"
)

func TestResolveTLSConfig(t *testing.T) {
	tests := []struct {
		name        string
		apiServer   *configv1.APIServer
		expectError bool
		validate    func(t *testing.T, config *tls.Config)
	}{
		{
			name:        "nil apiServer should return error",
			apiServer:   nil,
			expectError: true,
		},
		{
			name: "apiServer with no TLS profile should use intermediate",
			apiServer: &configv1.APIServer{
				Spec: configv1.APIServerSpec{},
			},
			expectError: false,
			validate: func(t *testing.T, config *tls.Config) {
				assert.Equal(t, uint16(tls.VersionTLS12), config.MinVersion)
				assert.Equal(t, uint16(tls.VersionTLS13), config.MaxVersion)
				assert.Equal(t, []string{"http/1.1"}, config.NextProtos)
				assert.NotEmpty(t, config.CipherSuites)
			},
		},
		{
			name: "modern profile should use TLS 1.3 only",
			apiServer: &configv1.APIServer{
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
				assert.Equal(t, []string{"http/1.1"}, config.NextProtos)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := profile.ResolveTLSConfig(tt.apiServer)

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

func TestResolveTLSProfileConfig(t *testing.T) {
	tests := []struct {
		name        string
		apiServer   *configv1.APIServer
		expectError bool
		expected    *profile.TLSProfileConfig
	}{
		{
			name: "old profile",
			apiServer: &configv1.APIServer{
				Spec: configv1.APIServerSpec{
					TLSSecurityProfile: &configv1.TLSSecurityProfile{
						Type: configv1.TLSProfileOldType,
					},
				},
			},
			expectError: false,
			expected: &profile.TLSProfileConfig{
				MinVersion: tls.VersionTLS10,
				MaxVersion: tls.VersionTLS13,
				NextProtos: []string{"http/1.1"},
			},
		},
		{
			name: "intermediate profile",
			apiServer: &configv1.APIServer{
				Spec: configv1.APIServerSpec{
					TLSSecurityProfile: &configv1.TLSSecurityProfile{
						Type: configv1.TLSProfileIntermediateType,
					},
				},
			},
			expectError: false,
			expected: &profile.TLSProfileConfig{
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS13,
				NextProtos: []string{"http/1.1"},
			},
		},
		{
			name: "modern profile",
			apiServer: &configv1.APIServer{
				Spec: configv1.APIServerSpec{
					TLSSecurityProfile: &configv1.TLSSecurityProfile{
						Type: configv1.TLSProfileModernType,
					},
				},
			},
			expectError: false,
			expected: &profile.TLSProfileConfig{
				MinVersion:   tls.VersionTLS13,
				MaxVersion:   tls.VersionTLS13,
				CipherSuites: []uint16{}, // TLS 1.3 doesn't use configurable cipher suites
				NextProtos:   []string{"http/1.1"},
			},
		},
		{
			name: "custom profile with valid config",
			apiServer: &configv1.APIServer{
				Spec: configv1.APIServerSpec{
					TLSSecurityProfile: &configv1.TLSSecurityProfile{
						Type: configv1.TLSProfileCustomType,
						Custom: &configv1.CustomTLSProfile{
							TLSProfileSpec: configv1.TLSProfileSpec{
								MinTLSVersion: configv1.VersionTLS12,
								Ciphers: []string{
									"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
									"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
								},
							},
						},
					},
				},
			},
			expectError: false,
			expected: &profile.TLSProfileConfig{
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS13, // Defaults to TLS 1.3
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				},
				NextProtos: []string{"http/1.1"},
			},
		},
		{
			name: "custom profile with invalid cipher",
			apiServer: &configv1.APIServer{
				Spec: configv1.APIServerSpec{
					TLSSecurityProfile: &configv1.TLSSecurityProfile{
						Type: configv1.TLSProfileCustomType,
						Custom: &configv1.CustomTLSProfile{
							TLSProfileSpec: configv1.TLSProfileSpec{
								MinTLSVersion: configv1.VersionTLS12,
								Ciphers:       []string{"INVALID_CIPHER"},
							},
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "unknown profile type",
			apiServer: &configv1.APIServer{
				Spec: configv1.APIServerSpec{
					TLSSecurityProfile: &configv1.TLSSecurityProfile{
						Type: configv1.TLSProfileType("UnknownType"),
					},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := profile.ResolveTLSProfileConfig(tt.apiServer)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, config)
			assert.Equal(t, tt.expected.MinVersion, config.MinVersion)
			assert.Equal(t, tt.expected.MaxVersion, config.MaxVersion)
			assert.Equal(t, tt.expected.NextProtos, config.NextProtos)

			if tt.expected.CipherSuites != nil {
				assert.Equal(t, tt.expected.CipherSuites, config.CipherSuites)
			} else {
				assert.NotEmpty(t, config.CipherSuites) // Should have some cipher suites
			}
		})
	}
}

func TestParseTLSVersion(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    uint16
		expectError bool
	}{
		{"TLS 1.0", "TLS1.0", tls.VersionTLS10, false},
		{"TLS 1.1", "TLS1.1", tls.VersionTLS11, false},
		{"TLS 1.2", "TLS1.2", tls.VersionTLS12, false},
		{"TLS 1.3", "TLS1.3", tls.VersionTLS13, false},
		{"TLSV1.2 format", "TLSV1.2", tls.VersionTLS12, false},
		{"lowercase", "tls1.2", tls.VersionTLS12, false},
		{"numeric format", "771", tls.VersionTLS12, false}, // 0x0303 = 771
		{"hex format", "0x0303", tls.VersionTLS12, false},
		{"invalid string", "invalid", 0, true},
		{"empty string", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := profile.ParseTLSVersion(tt.input)

			if tt.expectError {
				assert.Error(t, err)
				assert.ErrorIs(t, err, profile.ErrInvalidTLSVersion)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestResolveCipherSuites(t *testing.T) {
	tests := []struct {
		name        string
		input       []string
		expectError bool
		validate    func(t *testing.T, result []uint16)
	}{
		{
			name:  "empty slice",
			input: []string{},
			validate: func(t *testing.T, result []uint16) {
				assert.Nil(t, result)
			},
		},
		{
			name: "valid cipher suites",
			input: []string{
				"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			},
			validate: func(t *testing.T, result []uint16) {
				expected := []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				}
				assert.Equal(t, expected, result)
			},
		},
		{
			name:        "invalid cipher suite",
			input:       []string{"INVALID_CIPHER"},
			expectError: true,
		},
		{
			name: "mixed valid and invalid",
			input: []string{
				"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
				"INVALID_CIPHER",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := profile.ResolveCipherSuites(tt.input)

			if tt.expectError {
				assert.Error(t, err)
				assert.ErrorIs(t, err, profile.ErrInvalidCipherSuite)
				return
			}

			require.NoError(t, err)
			if tt.validate != nil {
				tt.validate(t, result)
			}
		})
	}
}

func TestValidateTLSConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *profile.TLSProfileConfig
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil config",
			config:      nil,
			expectError: true,
			errorMsg:    "TLS config cannot be nil",
		},
		{
			name: "MinVersion > MaxVersion",
			config: &profile.TLSProfileConfig{
				MinVersion: tls.VersionTLS13,
				MaxVersion: tls.VersionTLS12,
				NextProtos: []string{"http/1.1"},
			},
			expectError: true,
			errorMsg:    "MinVersion (772) cannot be greater than MaxVersion (771)",
		},
		{
			name: "MinVersion < TLS 1.2",
			config: &profile.TLSProfileConfig{
				MinVersion: tls.VersionTLS11,
				MaxVersion: tls.VersionTLS13,
				NextProtos: []string{"http/1.1"},
			},
			expectError: true,
			errorMsg:    "MinVersion (770) must be at least TLS 1.2 for security",
		},
		{
			name: "missing NextProtos",
			config: &profile.TLSProfileConfig{
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS13,
				NextProtos: []string{},
			},
			expectError: true,
			errorMsg:    "NextProtos must be specified",
		},
		{
			name: "valid config",
			config: &profile.TLSProfileConfig{
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS13,
				NextProtos: []string{"http/1.1"},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := profile.ValidateTLSConfig(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestTLSProfileConstants(t *testing.T) {
	// Verify our constants match the expected values
	assert.Equal(t, "TLS1.2", profile.TLSVersion12)
	assert.Equal(t, "TLS1.3", profile.TLSVersion13)

	// Verify profile type constants
	assert.Equal(t, "Old", profile.ProfileTypeOld)
	assert.Equal(t, "Intermediate", profile.ProfileTypeIntermediate)
	assert.Equal(t, "Modern", profile.ProfileTypeModern)
	assert.Equal(t, "Custom", profile.ProfileTypeCustom)

	// Verify default NextProtos
	assert.Equal(t, []string{"http/1.1"}, profile.DefaultNextProtos)
}
