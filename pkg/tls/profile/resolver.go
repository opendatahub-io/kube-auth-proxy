package profile

import (
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
)

// ResolveTLSConfig converts OpenShift APIServer TLS configuration to Go tls.Config
func ResolveTLSConfig(apiServer *configv1.APIServer) (*tls.Config, error) {
	if apiServer == nil {
		return nil, fmt.Errorf("apiServer cannot be nil")
	}

	profileConfig, err := ResolveTLSProfileConfig(apiServer)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve TLS profile: %w", err)
	}

	config := &tls.Config{ //nolint:gosec // MinVersion is intentionally set from the OpenShift TLS profile, which may include Old/TLS1.0 for compatibility
		MinVersion:   profileConfig.MinVersion,
		MaxVersion:   profileConfig.MaxVersion,
		CipherSuites: profileConfig.CipherSuites,
		NextProtos:   profileConfig.NextProtos,
	}

	return config, nil
}

// ResolveTLSProfileConfig resolves OpenShift APIServer spec to TLSProfileConfig
func ResolveTLSProfileConfig(apiServer *configv1.APIServer) (*TLSProfileConfig, error) {
	if apiServer.Spec.TLSSecurityProfile == nil {
		// Default to Intermediate profile when no profile is specified
		return getIntermediateProfile(), nil
	}

	profile := apiServer.Spec.TLSSecurityProfile
	switch profile.Type {
	case configv1.TLSProfileOldType:
		return getOldProfile(), nil
	case configv1.TLSProfileIntermediateType:
		return getIntermediateProfile(), nil
	case configv1.TLSProfileModernType:
		return getModernProfile(), nil
	case configv1.TLSProfileCustomType:
		return resolveCustomProfile(profile.Custom)
	default:
		return nil, fmt.Errorf("unknown TLS profile type: %s", profile.Type)
	}
}

// ParseTLSVersion converts string TLS version to uint16
func ParseTLSVersion(version string) (uint16, error) {
	switch strings.ToUpper(version) {
	case "TLS1.0", "TLSV1.0", "VERSIONTLS10":
		return tls.VersionTLS10, nil
	case "TLS1.1", "TLSV1.1", "VERSIONTLS11":
		return tls.VersionTLS11, nil
	case "TLS1.2", "TLSV1.2", "VERSIONTLS12":
		return tls.VersionTLS12, nil
	case "TLS1.3", "TLSV1.3", "VERSIONTLS13":
		return tls.VersionTLS13, nil
	default:
		// Try parsing as numeric value
		if num, err := strconv.ParseUint(version, 0, 16); err == nil {
			return uint16(num), nil
		}
		return 0, fmt.Errorf("%w: %s", ErrInvalidTLSVersion, version)
	}
}

// ResolveCipherSuites converts cipher suite names to IDs
func ResolveCipherSuites(cipherNames []string) ([]uint16, error) {
	if len(cipherNames) == 0 {
		return nil, nil
	}

	cipherNameMap := make(map[string]uint16)

	// Build map of available cipher suites
	for _, suite := range tls.CipherSuites() {
		cipherNameMap[suite.Name] = suite.ID
	}
	for _, suite := range tls.InsecureCipherSuites() {
		cipherNameMap[suite.Name] = suite.ID
	}

	result := make([]uint16, len(cipherNames))
	for i, name := range cipherNames {
		id, exists := cipherNameMap[name]
		if !exists {
			return nil, fmt.Errorf("%w: %s", ErrInvalidCipherSuite, name)
		}
		result[i] = id
	}

	return result, nil
}

// ValidateTLSConfig validates TLS configuration for security best practices
func ValidateTLSConfig(config *TLSProfileConfig) error {
	if config == nil {
		return fmt.Errorf("TLS config cannot be nil")
	}

	if config.MinVersion > config.MaxVersion {
		return fmt.Errorf("MinVersion (%d) cannot be greater than MaxVersion (%d)",
			config.MinVersion, config.MaxVersion)
	}

	if config.MinVersion < tls.VersionTLS12 {
		return fmt.Errorf("MinVersion (%d) must be at least TLS 1.2 for security", config.MinVersion)
	}

	if len(config.NextProtos) == 0 {
		return fmt.Errorf("NextProtos must be specified")
	}

	return nil
}

// getOldProfile returns the "Old" TLS profile configuration
func getOldProfile() *TLSProfileConfig {
	return &TLSProfileConfig{
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: getOldCipherSuites(),
		NextProtos:   DefaultNextProtos,
	}
}

// getIntermediateProfile returns the "Intermediate" TLS profile configuration
func getIntermediateProfile() *TLSProfileConfig {
	return &TLSProfileConfig{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: getIntermediateCipherSuites(),
		NextProtos:   DefaultNextProtos,
	}
}

// getModernProfile returns the "Modern" TLS profile configuration
func getModernProfile() *TLSProfileConfig {
	return &TLSProfileConfig{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{}, // TLS 1.3 doesn't use configurable cipher suites
		NextProtos:   DefaultNextProtos,
	}
}

// resolveCustomProfile handles custom TLS profile configuration
func resolveCustomProfile(custom *configv1.CustomTLSProfile) (*TLSProfileConfig, error) {
	if custom == nil {
		return nil, fmt.Errorf("custom profile cannot be nil")
	}

	spec := &custom.TLSProfileSpec

	minVersion, err := ParseTLSVersion(string(spec.MinTLSVersion))
	if err != nil {
		return nil, fmt.Errorf("invalid MinTLSVersion: %w", err)
	}

	// OpenShift doesn't specify MaxTLSVersion, so we'll default to TLS 1.3
	maxVersion := uint16(tls.VersionTLS13)

	cipherSuites, err := ResolveCipherSuites(spec.Ciphers)
	if err != nil {
		return nil, fmt.Errorf("invalid cipher suites: %w", err)
	}

	config := &TLSProfileConfig{
		MinVersion:   minVersion,
		MaxVersion:   maxVersion,
		CipherSuites: cipherSuites,
		NextProtos:   DefaultNextProtos,
	}

	return config, ValidateTLSConfig(config)
}

// getOldCipherSuites returns cipher suites for Old profile
func getOldCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	}
}

// getIntermediateCipherSuites returns cipher suites for Intermediate profile
func getIntermediateCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
}
