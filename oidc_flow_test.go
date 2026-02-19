//go:build integration

package main

import (
	"net/http"
	"net/http/cookiejar"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/options"
	"github.com/opendatahub-io/kube-auth-proxy/v1/test/integration/testutil"
	"golang.org/x/net/publicsuffix"
)

// buildOIDCOptions constructs options for the OIDC provider given the mock OIDC
// server and an upstream URL. opts.RawRedirectURL must be set by the caller.
func buildOIDCOptions(mockOIDC *testutil.MockOIDC, upstreamURL string) *options.Options {
	opts := options.NewOptions()
	opts.Cookie.Secret = "secretthirtytwobytes+abcdefghijk" // exactly 32 bytes
	opts.Cookie.Secure = false                               // httptest uses plain HTTP

	opts.Providers[0].ID = "oidc-integration-test"
	opts.Providers[0].Type = options.OIDCProvider
	opts.Providers[0].ClientID = mockOIDC.ClientID()
	opts.Providers[0].ClientSecret = mockOIDC.ClientSecret()
	opts.Providers[0].OIDCConfig.IssuerURL = mockOIDC.Issuer()
	opts.Providers[0].OIDCConfig.InsecureSkipNonce = true

	opts.EmailDomains = []string{"*"}
	// Skip the sign-in page so unauthenticated requests redirect to the OIDC provider.
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
	opts.InjectRequestHeaders = []options.Header{
		{
			Name: "X-Forwarded-Email",
			Values: []options.HeaderValue{
				{ClaimSource: &options.ClaimSource{Claim: "email"}},
			},
		},
	}
	return opts
}

var _ = Describe("OIDC OAuth Flow", func() {
	var (
		mockOIDC *testutil.MockOIDC
		upstream *testutil.TestUpstream
	)

	BeforeEach(func() {
		var err error
		mockOIDC, err = testutil.NewMockOIDC()
		Expect(err).ToNot(HaveOccurred())
		upstream = testutil.NewTestUpstream(http.StatusOK, "hello")
	})

	AfterEach(func() {
		upstream.Close()
		mockOIDC.Close()
	})

	It("redirects unauthenticated requests to the OIDC provider", func() {
		ln, proxyURL := newFreePortListener()
		opts := buildOIDCOptions(mockOIDC, upstream.URL())
		opts.RawRedirectURL = proxyURL + "/oauth2/callback"

		server := startProxyOnListener(opts, ln)
		defer server.Close()

		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // do not follow redirects
			},
		}
		resp, err := client.Get(server.URL + "/protected")
		Expect(err).ToNot(HaveOccurred())
		defer resp.Body.Close()

		// With SkipProviderButton=true the proxy skips the sign-in page and
		// issues a 302 redirect directly to the OIDC authorize endpoint.
		Expect(resp.StatusCode).To(Equal(http.StatusFound))
		loc := resp.Header.Get("Location")
		// The redirect must point to the OIDC provider's authorization endpoint.
		Expect(loc).To(ContainSubstring(mockOIDC.Issuer()))
	})

	It("completes full OIDC flow and forwards X-Forwarded-Email to upstream", func() {
		// Queue a user so mockOIDC can authenticate them.
		mockOIDC.QueueUser("alice@example.com", "alice", []string{"developers"})

		// Bind the proxy to a known port so that redirect_uri in the OAuth request
		// matches the actual server address.
		ln, proxyURL := newFreePortListener()
		opts := buildOIDCOptions(mockOIDC, upstream.URL())
		opts.RawRedirectURL = proxyURL + "/oauth2/callback"

		server := startProxyOnListener(opts, ln)
		defer server.Close()

		jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
		Expect(err).ToNot(HaveOccurred())

		client := &http.Client{Jar: jar}

		// This single request follows all redirects:
		// 1. GET /  → 302 → OIDC authorize endpoint
		// 2. OIDC authorize → 302 → /oauth2/callback?code=...&state=...
		// 3. /oauth2/callback exchanges code, sets session cookie → 302 → /
		// 4. GET / with session cookie → 200 from upstream
		resp, err := client.Get(server.URL + "/")
		Expect(err).ToNot(HaveOccurred())
		defer resp.Body.Close()

		Expect(resp.StatusCode).To(Equal(http.StatusOK))

		// Verify upstream received X-Forwarded-Email header.
		email := upstream.LastHeader("X-Forwarded-Email")
		Expect(strings.ToLower(email)).To(Equal("alice@example.com"))
	})
})
