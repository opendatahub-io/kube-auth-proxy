package profile

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/logger"
	configv1 "github.com/openshift/api/config/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	configinformer "github.com/openshift/client-go/config/informers/externalversions"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// APIServerName is the name of the cluster APIServer object
	APIServerName = "cluster"
	// DefaultResyncInterval is the default interval for informer resyncs
	DefaultResyncInterval = 10 * time.Minute
)

// OpenShiftProfileClient implements ProfileManager interface using OpenShift config API
type OpenShiftProfileClient struct {
	client       configclient.Interface
	informer     cache.SharedIndexInformer
	stopCh       chan struct{}
	callbacks    []UpdateCallback
	mu           sync.RWMutex
	watching     bool
	stopChClosed bool
}

// NewOpenShiftProfileClient creates a new OpenShiftProfileClient
func NewOpenShiftProfileClient(kubeconfig string) (*OpenShiftProfileClient, error) {
	config, err := buildClientConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build client config: %w", err)
	}

	client, err := configclient.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenShift config client: %w", err)
	}

	return newOpenShiftProfileClientWithClient(client), nil
}

// newOpenShiftProfileClientWithClient creates a client with an injected configclient (for testing)
func newOpenShiftProfileClientWithClient(client configclient.Interface) *OpenShiftProfileClient {
	return &OpenShiftProfileClient{
		client:    client,
		stopCh:    make(chan struct{}),
		callbacks: make([]UpdateCallback, 0),
	}
}

// NewOpenShiftProfileClientForTesting creates a client with injected configclient for testing
func NewOpenShiftProfileClientForTesting(client configclient.Interface) *OpenShiftProfileClient {
	return newOpenShiftProfileClientWithClient(client)
}

// GetTLSConfig fetches the current TLS configuration from the cluster
func (c *OpenShiftProfileClient) GetTLSConfig(ctx context.Context) (*tls.Config, error) {
	apiServer, err := c.FetchTLSProfile(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch TLS profile: %w", err)
	}

	return ResolveTLSConfig(apiServer)
}

// FetchTLSProfile fetches the APIServer object from the cluster
func (c *OpenShiftProfileClient) FetchTLSProfile(ctx context.Context) (*configv1.APIServer, error) {
	apiServer, err := c.client.ConfigV1().APIServers().Get(ctx, APIServerName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get APIServer '%s': %w", APIServerName, err)
	}

	return apiServer, nil
}

// StartWatching begins watching for TLS profile changes
func (c *OpenShiftProfileClient) StartWatching(ctx context.Context, callback UpdateCallback) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.watching {
		return ErrWatcherAlreadyStarted
	}

	// Reset stopCh if it was previously closed
	if c.stopChClosed {
		c.stopCh = make(chan struct{})
		c.stopChClosed = false
	}

	c.callbacks = append(c.callbacks, callback)

	if err := c.setupInformer(); err != nil {
		return fmt.Errorf("failed to setup informer: %w", err)
	}

	go c.runInformer(ctx)
	c.watching = true

	return nil
}

// Stop stops the profile watcher and cleans up resources
func (c *OpenShiftProfileClient) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.watching {
		return nil
	}

	if !c.stopChClosed {
		close(c.stopCh)
		c.stopChClosed = true
	}
	c.watching = false
	c.callbacks = nil

	return nil
}

// IsWatching returns true if the client is currently watching for changes
func (c *OpenShiftProfileClient) IsWatching() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.watching
}

// setupInformer creates and configures the APIServer informer
func (c *OpenShiftProfileClient) setupInformer() error {
	factory := configinformer.NewSharedInformerFactory(c.client, DefaultResyncInterval)

	c.informer = factory.Config().V1().APIServers().Informer()

	// Add event handlers
	c.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.handleAPIServerAdd,
		UpdateFunc: c.handleAPIServerUpdate,
		DeleteFunc: c.handleAPIServerDelete,
	})

	return nil
}

// runInformer starts the informer and waits for it to stop
func (c *OpenShiftProfileClient) runInformer(ctx context.Context) {
	informerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		select {
		case <-c.stopCh:
			cancel()
		case <-ctx.Done():
			cancel()
		}
	}()

	c.informer.Run(informerCtx.Done())
}

// handleAPIServerAdd handles addition of APIServer objects
func (c *OpenShiftProfileClient) handleAPIServerAdd(obj interface{}) {
	apiServer, ok := obj.(*configv1.APIServer)
	if !ok {
		return
	}

	if apiServer.Name == APIServerName {
		c.notifyCallbacks(apiServer)
	}
}

// handleAPIServerUpdate handles updates to APIServer objects
func (c *OpenShiftProfileClient) handleAPIServerUpdate(oldObj, newObj interface{}) {
	newAPIServer, ok := newObj.(*configv1.APIServer)
	if !ok {
		return
	}

	if newAPIServer.Name != APIServerName {
		return
	}

	oldAPIServer, ok := oldObj.(*configv1.APIServer)
	if ok && c.isTLSProfileChanged(oldAPIServer, newAPIServer) {
		c.notifyCallbacks(newAPIServer)
	}
}

// handleAPIServerDelete handles deletion of APIServer objects
func (c *OpenShiftProfileClient) handleAPIServerDelete(obj interface{}) {
	// Handle tombstone objects
	if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = tombstone.Obj
	}

	apiServer, ok := obj.(*configv1.APIServer)
	if !ok {
		return
	}

	if apiServer.Name == APIServerName {
		// APIServer deleted - this is unusual, but we should notify
		c.notifyCallbacks(apiServer)
	}
}

// isTLSProfileChanged checks if TLS security profile has changed between two APIServer objects
func (c *OpenShiftProfileClient) isTLSProfileChanged(old, updated *configv1.APIServer) bool {
	if old.Spec.TLSSecurityProfile == nil && updated.Spec.TLSSecurityProfile == nil {
		return false
	}

	if old.Spec.TLSSecurityProfile == nil || updated.Spec.TLSSecurityProfile == nil {
		return true
	}

	// Compare profile types
	if old.Spec.TLSSecurityProfile.Type != updated.Spec.TLSSecurityProfile.Type {
		return true
	}

	// For custom profiles, compare the actual configuration
	if updated.Spec.TLSSecurityProfile.Type == configv1.TLSProfileCustomType {
		return c.isCustomProfileChanged(old.Spec.TLSSecurityProfile.Custom, updated.Spec.TLSSecurityProfile.Custom)
	}

	return false
}

// isCustomProfileChanged compares two custom TLS profiles
func (c *OpenShiftProfileClient) isCustomProfileChanged(old, updated *configv1.CustomTLSProfile) bool {
	if old == nil && updated == nil {
		return false
	}
	if old == nil || updated == nil {
		return true
	}

	oldSpec := &old.TLSProfileSpec
	newSpec := &updated.TLSProfileSpec

	if oldSpec.MinTLSVersion != newSpec.MinTLSVersion {
		return true
	}

	// Compare cipher suites
	if len(oldSpec.Ciphers) != len(newSpec.Ciphers) {
		return true
	}

	for i, cipher := range oldSpec.Ciphers {
		if cipher != newSpec.Ciphers[i] {
			return true
		}
	}

	return false
}

// notifyCallbacks calls all registered callbacks with the new TLS configuration
func (c *OpenShiftProfileClient) notifyCallbacks(apiServer *configv1.APIServer) {
	tlsConfig, err := ResolveTLSConfig(apiServer)
	if err != nil {
		logger.Errorf("Failed to resolve TLS configuration from APIServer.tlsSecurityProfile inside notifyCallbacks: %v", err)
		return
	}

	c.mu.RLock()
	callbacks := make([]UpdateCallback, len(c.callbacks))
	copy(callbacks, c.callbacks)
	c.mu.RUnlock()

	for _, callback := range callbacks {
		if err := callback(tlsConfig); err != nil {
			logger.Errorf("Failed to notify callback: %v", err)
		}
	}
}

// buildClientConfig builds a Kubernetes client configuration
func buildClientConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}
