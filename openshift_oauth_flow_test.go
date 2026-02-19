//go:build integration

package main

import (
	"net/http"
	"net/http/cookiejar"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/options"
	"github.com/opendatahub-io/kube-auth-proxy/v1/test/integration/testutil"
	"golang.org/x/net/publicsuffix"
)

// buildOpenShiftOptions constructs options for the OpenShift OAuth provider.
// opts.RawRedirectURL must be set by the caller before validation.
func buildOpenShiftOptions(mock *testutil.MockOpenShiftOAuth, upstreamURL string) *options.Options {
	opts := options.NewOptions()
	opts.Cookie.Secret = "secretthirtytwobytes+abcdefghijk" // exactly 32 bytes
	opts.Cookie.Secure = false                               // httptest uses plain HTTP

	opts.Providers[0].ID = "openshift-integration-test"
	opts.Providers[0].Type = options.OpenShiftProvider
	opts.Providers[0].ClientID = "openshift-test-client"
	opts.Providers[0].ClientSecret = "openshift-test-secret"

	// Set all three URLs explicitly so the provider does not try to auto-discover
	// via the Kubernetes API (which is unavailable in tests).
	opts.Providers[0].LoginURL = mock.AuthorizeURL()
	opts.Providers[0].RedeemURL = mock.TokenURL()
	opts.Providers[0].ValidateURL = mock.UserInfoURL()

	opts.EmailDomains = []string{"*"}
	// Skip the sign-in page so unauthenticated requests redirect to the provider.
	opts.SkipProviderButton = true

	opts.UpstreamServers = options.UpstreamConfig{
		Upstreams: []options.Upstream{
			{
				ID:   "upstream",
				Path: "/",
				URI:  upstreamURL,
			},
		},
	}
	// Inject X-Forwarded-User (maps to the "user" claim set by the OpenShift provider)
	// and X-Forwarded-Email (maps to the "email" claim).
	opts.InjectRequestHeaders = []options.Header{
		{
			Name: "X-Forwarded-User",
			Values: []options.HeaderValue{
				{ClaimSource: &options.ClaimSource{Claim: "user"}},
			},
		},
		{
			Name: "X-Forwarded-Email",
			Values: []options.HeaderValue{
				{ClaimSource: &options.ClaimSource{Claim: "email"}},
			},
		},
	}
	return opts
}

var _ = Describe("OpenShift OAuth Flow", func() {
	var (
		mockOS   *testutil.MockOpenShiftOAuth
		upstream *testutil.TestUpstream
	)

	BeforeEach(func() {
		mockOS = testutil.NewMockOpenShiftOAuth("bob", "bob@example.com")
		upstream = testutil.NewTestUpstream(http.StatusOK, "hello")
	})

	AfterEach(func() {
		upstream.Close()
		mockOS.Close()
	})

	It("redirects unauthenticated requests to the OpenShift authorization endpoint", func() {
		ln, proxyURL := newFreePortListener()
		opts := buildOpenShiftOptions(mockOS, upstream.URL())
		opts.RawRedirectURL = proxyURL + "/oauth2/callback"

		server, _ := startProxyOnListener(opts, ln)
		defer server.Close()

		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := client.Get(server.URL + "/protected")
		Expect(err).ToNot(HaveOccurred())
		defer resp.Body.Close()

		Expect(resp.StatusCode).To(Equal(http.StatusFound))
		loc := resp.Header.Get("Location")
		// Redirect must point to the mock OpenShift authorization endpoint.
		Expect(loc).To(ContainSubstring(mockOS.URL()))
	})

	It("completes full OpenShift OAuth flow and forwards X-Forwarded-User to upstream", func() {
		ln, proxyURL := newFreePortListener()
		opts := buildOpenShiftOptions(mockOS, upstream.URL())
		opts.RawRedirectURL = proxyURL + "/oauth2/callback"

		server, _ := startProxyOnListener(opts, ln)
		defer server.Close()

		jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
		Expect(err).ToNot(HaveOccurred())

		client := &http.Client{Jar: jar}

		// The full flow:
		// 1. GET /  → 302 → OpenShift authorize endpoint
		// 2. Mock authorize → 302 → /oauth2/callback?code=...&state=...
		// 3. Callback: POST token exchange → EnrichSession (user info) → 302 → /
		// 4. GET / with session cookie → 200 from upstream
		resp, err := client.Get(server.URL + "/")
		Expect(err).ToNot(HaveOccurred())
		defer resp.Body.Close()

		Expect(resp.StatusCode).To(Equal(http.StatusOK))

		// Verify the upstream received the injected headers.
		user := upstream.LastHeader("X-Forwarded-User")
		Expect(user).To(Equal("bob"))
	})
})
