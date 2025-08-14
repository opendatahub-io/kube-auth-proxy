package persistence

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/options"
	sessionsapi "github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/sessions"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/sessions/tests"
)

var _ = Describe("Persistence Manager Tests", func() {
	var ms *tests.MockStore
	BeforeEach(func() {
		ms = tests.NewMockStore()
	})
	tests.RunSessionStoreTests(
		func(_ *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
			return NewManager(ms, cookieOpts), nil
		},
		func(d time.Duration) error {
			ms.FastForward(d)
			return nil
		})
})
