//go:build integration

package main

import (
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/opendatahub-io/kube-auth-proxy/v1/test/integration/testutil"
)

var _ = Describe("Edge Cases", func() {
	var (
		mockOIDC *testutil.MockOIDC
		upstream *testutil.TestUpstream
	)

	BeforeEach(func() {
		var err error
		mockOIDC, err = testutil.NewMockOIDC()
		Expect(err).ToNot(HaveOccurred())
		upstream = testutil.NewTestUpstream(http.StatusOK, "ok")
	})

	AfterEach(func() {
		upstream.Close()
		mockOIDC.Close()
	})

	Describe("CSRF protection", func() {
		// Direct callback hit without a prior login and without a CSRF cookie.
		// The proxy must reject the request: it may return 403, 500, or redirect
		// back to sign-in — anything but 200.
		It("rejects a callback with a fake state and no CSRF cookie", func() {
			ln, proxyURL := newFreePortListener()
			opts := buildOIDCOptions(mockOIDC, upstream.URL())
			opts.RawRedirectURL = proxyURL + "/oauth2/callback"

			server, _ := startProxyOnListener(opts, ln)
			defer server.Close()

			// Do not follow redirects so we see the exact first response.
			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			// Hit the callback directly without a prior login flow:
			// no CSRF cookie, fake code and state parameters.
			resp, err := client.Get(server.URL + "/oauth2/callback?code=fake&state=fake")
			Expect(err).ToNot(HaveOccurred())
			defer resp.Body.Close()

			// The response must not be 200 OK — CSRF validation must have failed.
			Expect(resp.StatusCode).NotTo(Equal(http.StatusOK))
		})
	})

	Describe("Open redirect protection", func() {
		// An attacker passes rd=https://evil.example.com/steal to /oauth2/start.
		// The proxy must not redirect the user to evil.example.com at any point.
		It("does not redirect to an external domain not in whitelist", func() {
			ln, proxyURL := newFreePortListener()
			opts := buildOIDCOptions(mockOIDC, upstream.URL())
			opts.RawRedirectURL = proxyURL + "/oauth2/callback"
			// No WhitelistDomains → external redirects are never allowed.

			server, _ := startProxyOnListener(opts, ln)
			defer server.Close()

			client := &http.Client{
				// Stop at the first redirect so we can inspect the Location header.
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			// Request the start of the OAuth flow with a malicious rd parameter.
			resp, err := client.Get(server.URL + "/oauth2/start?rd=https://evil.example.com/steal")
			Expect(err).ToNot(HaveOccurred())
			defer resp.Body.Close()

			// The response must be a redirect (302).
			Expect(resp.StatusCode).To(Equal(http.StatusFound))

			// The redirect destination (Location header) must not point to evil.example.com.
			// The proxy validates the rd parameter against the whitelist and falls back to "/" when
			// the domain is not allowed, so the Location must be safe (i.e. the OIDC provider URL).
			loc := resp.Header.Get("Location")
			Expect(loc).NotTo(ContainSubstring("evil.example.com"))
		})
	})
})
