package testutil_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/opendatahub-io/kube-auth-proxy/v1/test/integration/testutil"
)

var _ = Describe("MockOIDC", func() {
	It("starts and exposes issuer, clientID, clientSecret", func() {
		m, err := testutil.NewMockOIDC()
		Expect(err).ToNot(HaveOccurred())
		defer m.Close()

		Expect(m.Issuer()).ToNot(BeEmpty())
		Expect(m.ClientID()).ToNot(BeEmpty())
		Expect(m.ClientSecret()).ToNot(BeEmpty())
	})

	It("accepts queued users", func() {
		m, err := testutil.NewMockOIDC()
		Expect(err).ToNot(HaveOccurred())
		defer m.Close()

		m.QueueUser("test@example.com", "testuser", []string{"devs"})
		Expect(m.AddedUserCount()).To(Equal(1))
	})
})
