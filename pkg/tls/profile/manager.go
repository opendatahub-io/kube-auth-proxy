package profile

import (
	"context"
	"crypto/tls"
)

// Manager defines the interface for managing TLS profiles from OpenShift cluster
type Manager interface {
	// GetTLSConfig fetches the current TLS configuration based on the cluster's TLS profile
	GetTLSConfig(ctx context.Context) (*tls.Config, error)

	// StartWatching begins watching for TLS profile changes and calls the callback
	// when changes are detected. Only one watcher can be active at a time.
	StartWatching(ctx context.Context, callback UpdateCallback) error

	// Stop stops the profile watcher and cleans up resources
	Stop() error

	// IsWatching returns true if the profile manager is currently watching for changes
	IsWatching() bool
}

// NewProfileManager creates a new Manager instance based on the configuration
func NewProfileManager(kubeconfig string) (Manager, error) {
	return NewOpenShiftProfileClient(kubeconfig)
}
