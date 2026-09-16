package tls

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/logger"
	configv1 "github.com/openshift/api/config/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
)

type ProfileWatcher struct {
	resource dynamic.ResourceInterface

	lastProfile   *configv1.TLSSecurityProfile
	lastAdherence configv1.TLSAdherencePolicy
}

// Run watches the APIServer profile and calls onChange when its profile or
// adherence policy changes. The caller should cancel the proxy context from
// onChange so the Deployment restarts with the new TLS settings.
func (w *ProfileWatcher) Run(ctx context.Context, onChange func()) error {
	for {
		if err := w.watchOnce(ctx, onChange); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) {
				return err
			}
			logger.Printf("WARNING: TLS profile watch failed, retrying: %v", err)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}
	}
}

func (w *ProfileWatcher) watchOnce(ctx context.Context, onChange func()) error {
	resourceVersion, err := w.reconcileCurrent(ctx, onChange)
	if err != nil {
		return err
	}

	stream, err := w.resource.Watch(ctx, metav1.ListOptions{
		ResourceVersion:     resourceVersion,
		AllowWatchBookmarks: true,
	})
	if err != nil {
		return err
	}
	defer stream.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-stream.ResultChan():
			if !ok {
				return fmt.Errorf("TLS profile watch closed")
			}
			switch event.Type {
			case watch.Added, watch.Modified:
				object, ok := event.Object.(interface{ UnstructuredContent() map[string]interface{} })
				if !ok {
					return fmt.Errorf("TLS profile watch returned unexpected object %T", event.Object)
				}
				apiServer, err := decodeAPIServerFromMap(object.UnstructuredContent())
				if err != nil {
					return fmt.Errorf("decoding TLS profile watch event: %w", err)
				}
				w.notifyIfChanged(cloneProfile(apiServer.Spec.TLSSecurityProfile), apiServer.Spec.TLSAdherence, onChange)
			case watch.Deleted:
				w.notifyIfChanged(nil, configv1.TLSAdherencePolicyNoOpinion, onChange)
			case watch.Error:
				return apierrors.FromObject(event.Object)
			}
		}
	}
}

func (w *ProfileWatcher) reconcileCurrent(ctx context.Context, onChange func()) (string, error) {
	list, err := w.resource.List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", err
	}

	currentProfile := (*configv1.TLSSecurityProfile)(nil)
	currentAdherence := configv1.TLSAdherencePolicyNoOpinion
	for i := range list.Items {
		if list.Items[i].GetName() != apiServerName {
			continue
		}
		apiServer, err := decodeAPIServerFromMap(list.Items[i].UnstructuredContent())
		if err != nil {
			return "", fmt.Errorf("decoding current TLS profile: %w", err)
		}
		currentProfile = cloneProfile(apiServer.Spec.TLSSecurityProfile)
		currentAdherence = apiServer.Spec.TLSAdherence
		break
	}
	w.notifyIfChanged(currentProfile, currentAdherence, onChange)
	return list.GetResourceVersion(), nil
}

func (w *ProfileWatcher) notifyIfChanged(profile *configv1.TLSSecurityProfile, adherence configv1.TLSAdherencePolicy, onChange func()) {
	if reflect.DeepEqual(w.lastProfile, profile) && w.lastAdherence == adherence {
		return
	}
	w.lastProfile = profile
	w.lastAdherence = adherence
	onChange()
}

func decodeAPIServerFromMap(object map[string]interface{}) (*configv1.APIServer, error) {
	return decodeAPIServer(&unstructured.Unstructured{Object: object})
}
