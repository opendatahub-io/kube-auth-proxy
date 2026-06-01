package profile

import (
	"crypto/tls"
	"errors"
)

// TLSProfileConfig represents resolved TLS configuration from OpenShift TLS profile
type TLSProfileConfig struct {
	MinVersion   uint16
	MaxVersion   uint16
	CipherSuites []uint16
	NextProtos   []string
}

// UpdateCallback is called when TLS profile changes are detected
type UpdateCallback func(*tls.Config) error

// Common errors
var (
	ErrProfileNotFound       = errors.New("TLS profile not found")
	ErrInvalidTLSVersion     = errors.New("invalid TLS version")
	ErrInvalidCipherSuite    = errors.New("invalid cipher suite")
	ErrProfileManagerStopped = errors.New("profile manager stopped")
	ErrWatcherAlreadyStarted = errors.New("watcher already started")
)

// TLS version constants for easier testing and validation
const (
	TLSVersion12 = "TLS1.2"
	TLSVersion13 = "TLS1.3"
)

// TLS profile type constants from OpenShift
const (
	ProfileTypeOld          = "Old"
	ProfileTypeIntermediate = "Intermediate"
	ProfileTypeModern       = "Modern"
	ProfileTypeCustom       = "Custom"
)

// DefaultNextProtos defines the default protocols for CVE mitigation
var DefaultNextProtos = []string{"http/1.1"}
