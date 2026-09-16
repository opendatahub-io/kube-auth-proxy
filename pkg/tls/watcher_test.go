package tls

import (
	"context"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestProfileWatcherNotifiesProfileAndAdherenceChanges(t *testing.T) {
	watcher := &ProfileWatcher{
		lastProfile:   &configv1.TLSSecurityProfile{Type: configv1.TLSProfileIntermediateType},
		lastAdherence: configv1.TLSAdherencePolicyNoOpinion,
	}

	changes := 0
	watcher.notifyIfChanged(
		&configv1.TLSSecurityProfile{Type: configv1.TLSProfileModernType},
		configv1.TLSAdherencePolicyStrictAllComponents,
		func() { changes++ },
	)
	if changes != 1 {
		t.Fatalf("changes = %d, want 1", changes)
	}

	watcher.notifyIfChanged(
		&configv1.TLSSecurityProfile{Type: configv1.TLSProfileModernType},
		configv1.TLSAdherencePolicyStrictAllComponents,
		func() { changes++ },
	)
	if changes != 1 {
		t.Fatalf("unchanged profile triggered another change: %d", changes)
	}
}

func TestProfileWatcherReconcilesCurrentStateBeforeWatch(t *testing.T) {
	object := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "config.openshift.io/v1",
		"kind":       "APIServer",
		"metadata": map[string]interface{}{
			"name": apiServerName,
		},
		"spec": map[string]interface{}{
			"tlsAdherence": string(configv1.TLSAdherencePolicyStrictAllComponents),
			"tlsSecurityProfile": map[string]interface{}{
				"type": string(configv1.TLSProfileModernType),
			},
		},
	}}
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), object)
	watcher := &ProfileWatcher{
		resource:      client.Resource(apiServerGVR),
		lastProfile:   &configv1.TLSSecurityProfile{Type: configv1.TLSProfileIntermediateType},
		lastAdherence: configv1.TLSAdherencePolicyNoOpinion,
	}

	changes := 0
	if _, err := watcher.reconcileCurrent(context.Background(), func() { changes++ }); err != nil {
		t.Fatalf("reconcileCurrent() returned an error: %v", err)
	}
	if changes != 1 {
		t.Fatalf("changes = %d, want 1", changes)
	}
	if watcher.lastProfile.Type != configv1.TLSProfileModernType {
		t.Fatalf("lastProfile = %q, want %q", watcher.lastProfile.Type, configv1.TLSProfileModernType)
	}
	if watcher.lastAdherence != configv1.TLSAdherencePolicyStrictAllComponents {
		t.Fatalf("lastAdherence = %q, want %q", watcher.lastAdherence, configv1.TLSAdherencePolicyStrictAllComponents)
	}
}
