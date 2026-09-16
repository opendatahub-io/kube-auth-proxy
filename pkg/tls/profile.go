package tls

import (
	"context"
	cryptotls "crypto/tls"
	"errors"
	"fmt"

	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/logger"
	configv1 "github.com/openshift/api/config/v1"
	libgocrypto "github.com/openshift/library-go/pkg/crypto"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const apiServerName = "cluster"

var apiServerGVR = schema.GroupVersionResource{
	Group:    "config.openshift.io",
	Version:  "v1",
	Resource: "apiservers",
}

var tlsVersions = map[configv1.TLSProtocolVersion]uint16{
	"VersionTLS10": cryptotls.VersionTLS10,
	"VersionTLS11": cryptotls.VersionTLS11,
	"VersionTLS12": cryptotls.VersionTLS12,
	"VersionTLS13": cryptotls.VersionTLS13,
}

type Result struct {
	TLSOpts         []func(*cryptotls.Config)
	ObservedProfile *configv1.TLSSecurityProfile
	AdherencePolicy configv1.TLSAdherencePolicy
	ProfileFetched  bool
}

// Resolve reads the cluster TLS profile when the proxy is running in a
// cluster. Non-OpenShift and local executions retain the proxy's existing TLS
// defaults.
func Resolve(ctx context.Context, kubeconfig string) (Result, *ProfileWatcher, error) {
	config, err := restConfig(kubeconfig)
	if err != nil {
		if shouldUsePortableDefaults(kubeconfig, err) {
			return Result{}, nil, nil
		}
		return Result{}, nil, fmt.Errorf("building Kubernetes client config: %w", err)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return Result{}, nil, fmt.Errorf("creating Kubernetes dynamic client: %w", err)
	}
	resourceClient := dynamicClient.Resource(apiServerGVR)
	watcher := &ProfileWatcher{resource: resourceClient}

	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return Result{}, nil, fmt.Errorf("creating Kubernetes discovery client: %w", err)
	}
	if _, err := discoveryClient.ServerResourcesForGroupVersion(apiServerGVR.Group + "/" + apiServerGVR.Version); err != nil {
		if meta.IsNoMatchError(err) || apierrors.IsNotFound(err) {
			return Result{}, nil, nil
		}
		return Result{}, nil, fmt.Errorf("discovering OpenShift config API: %w", err)
	}

	object, err := resourceClient.Get(ctx, apiServerName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return Result{}, nil, fmt.Errorf("reading OpenShift APIServer TLS profile: %w", err)
		}
		if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) {
			return Result{}, nil, fmt.Errorf("reading OpenShift APIServer TLS profile: %w", err)
		}
		return Result{}, nil, fmt.Errorf("reading OpenShift APIServer TLS profile: %w", err)
	}

	apiServer, err := decodeAPIServer(object)
	if err != nil {
		return Result{}, nil, fmt.Errorf("decoding OpenShift APIServer TLS profile: %w", err)
	}
	result := Result{
		ObservedProfile: cloneProfile(apiServer.Spec.TLSSecurityProfile),
		AdherencePolicy: apiServer.Spec.TLSAdherence,
		ProfileFetched:  true,
	}
	watcher.lastProfile = cloneProfile(result.ObservedProfile)
	watcher.lastAdherence = result.AdherencePolicy

	spec, err := profileSpec(apiServer.Spec.TLSSecurityProfile)
	if err != nil {
		if shouldHonorProfile(result.AdherencePolicy) {
			return Result{}, nil, fmt.Errorf("invalid Strict TLS profile: %w", err)
		}
		logger.Printf("WARNING: invalid legacy TLS profile, preserving proxy defaults: %v", err)
		return result, watcher, nil
	}

	if shouldHonorProfile(result.AdherencePolicy) {
		result.TLSOpts, err = tlsOpts(spec)
		if err != nil {
			return Result{}, nil, fmt.Errorf("invalid Strict TLS profile: %w", err)
		}
	}
	return result, watcher, nil
}

func restConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}

func shouldUsePortableDefaults(kubeconfig string, err error) bool {
	return kubeconfig == "" && errors.Is(err, rest.ErrNotInCluster)
}

func decodeAPIServer(object *unstructured.Unstructured) (*configv1.APIServer, error) {
	apiServer := &configv1.APIServer{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, apiServer); err != nil {
		return nil, err
	}
	return apiServer, nil
}

func profileSpec(profile *configv1.TLSSecurityProfile) (configv1.TLSProfileSpec, error) {
	if profile == nil {
		return configv1.TLSProfileSpec{}, errors.New("TLS security profile is missing")
	}
	switch profile.Type {
	case configv1.TLSProfileCustomType:
		if profile.Custom == nil {
			return configv1.TLSProfileSpec{}, errors.New("custom TLS security profile is missing its Custom settings")
		}
		return profile.Custom.TLSProfileSpec, nil
	case configv1.TLSProfileOldType, configv1.TLSProfileIntermediateType, configv1.TLSProfileModernType:
		return *configv1.TLSProfiles[profile.Type], nil
	case "":
		return configv1.TLSProfileSpec{}, errors.New("TLS security profile type is empty")
	default:
		return configv1.TLSProfileSpec{}, fmt.Errorf("unsupported TLS security profile type %q", profile.Type)
	}
}

func tlsOpts(profile configv1.TLSProfileSpec) ([]func(*cryptotls.Config), error) {
	minVersion, ok := tlsVersions[profile.MinTLSVersion]
	if !ok {
		return nil, fmt.Errorf("unsupported minimum TLS version %q", profile.MinTLSVersion)
	}

	ciphers, unsupportedCiphers := cipherCodes(profile.Ciphers)
	for _, cipher := range unsupportedCiphers {
		logger.Printf("WARNING: dropping unsupported TLS cipher %q", cipher)
	}
	if len(profile.Ciphers) > 0 && len(ciphers) == 0 {
		return nil, errors.New("TLS profile has no cipher suites supported by Go")
	}

	groups, unsupportedGroups := libgocrypto.TLSGroupsToCurveIDs(profile.Groups)
	for _, group := range unsupportedGroups {
		logger.Printf("WARNING: dropping unsupported TLS group %q", group)
	}
	if len(profile.Groups) > 0 && len(groups) == 0 {
		return nil, errors.New("TLS profile has no groups supported by Go")
	}

	return []func(*cryptotls.Config){func(config *cryptotls.Config) {
		config.MinVersion = minVersion
		if minVersion == cryptotls.VersionTLS13 {
			config.CipherSuites = nil
		} else if len(ciphers) > 0 {
			config.CipherSuites = ciphers
		}
		if len(groups) > 0 {
			config.CurvePreferences = groups
		}
	}}, nil
}

func cipherCodes(names []string) (codes []uint16, unsupported []string) {
	for _, name := range names {
		if code, err := libgocrypto.CipherSuite(name); err == nil {
			codes = append(codes, code)
			continue
		}
		ianaNames := libgocrypto.OpenSSLToIANACipherSuites([]string{name})
		if len(ianaNames) != 1 {
			unsupported = append(unsupported, name)
			continue
		}
		code, err := libgocrypto.CipherSuite(ianaNames[0])
		if err != nil {
			unsupported = append(unsupported, name)
			continue
		}
		codes = append(codes, code)
	}
	return codes, unsupported
}

func shouldHonorProfile(policy configv1.TLSAdherencePolicy) bool {
	switch policy {
	case configv1.TLSAdherencePolicyNoOpinion, configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly:
		return false
	case configv1.TLSAdherencePolicyStrictAllComponents:
		return true
	default:
		logger.Printf("WARNING: unknown TLS adherence policy %q, treating it as Strict", policy)
		return true
	}
}

func cloneProfile(profile *configv1.TLSSecurityProfile) *configv1.TLSSecurityProfile {
	if profile == nil {
		return nil
	}
	return profile.DeepCopy()
}
