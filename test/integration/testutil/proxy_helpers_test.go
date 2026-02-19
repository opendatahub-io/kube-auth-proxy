package testutil_test

import (
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/opendatahub-io/kube-auth-proxy/v1/test/integration/testutil"
)

var _ = Describe("TestUpstream", func() {
	It("records requests and returns configured response", func() {
		up := testutil.NewTestUpstream(http.StatusOK, "hello")
		defer up.Close()

		resp, err := http.Get(up.URL())
		Expect(err).ToNot(HaveOccurred())
		defer resp.Body.Close()

		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		Expect(up.RequestCount()).To(Equal(1))
	})

	It("captures headers from last request", func() {
		up := testutil.NewTestUpstream(http.StatusOK, "ok")
		defer up.Close()

		req, _ := http.NewRequest("GET", up.URL(), nil)
		req.Header.Set("X-Forwarded-User", "alice")
		http.DefaultClient.Do(req) //nolint:errcheck

		Expect(up.LastHeader("X-Forwarded-User")).To(Equal("alice"))
	})
})
