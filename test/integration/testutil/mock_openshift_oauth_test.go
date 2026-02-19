package testutil_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/opendatahub-io/kube-auth-proxy/v1/test/integration/testutil"
)

var _ = Describe("MockOpenShiftOAuth", func() {
	var mock *testutil.MockOpenShiftOAuth

	BeforeEach(func() {
		mock = testutil.NewMockOpenShiftOAuth("testuser", "testuser@cluster.local")
	})
	AfterEach(func() { mock.Close() })

	It("serves discovery endpoint", func() {
		resp, err := http.Get(mock.URL() + "/.well-known/oauth-authorization-server")
		Expect(err).ToNot(HaveOccurred())
		defer resp.Body.Close()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))

		var doc map[string]string
		Expect(json.NewDecoder(resp.Body).Decode(&doc)).To(Succeed())
		Expect(doc["authorization_endpoint"]).To(ContainSubstring("/oauth/authorize"))
		Expect(doc["token_endpoint"]).To(ContainSubstring("/oauth/token"))
	})

	It("authorize redirects with code", func() {
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		resp, err := client.Get(mock.URL() + "/oauth/authorize?client_id=x&response_type=code&redirect_uri=http://localhost/cb&state=s")
		Expect(err).ToNot(HaveOccurred())
		defer resp.Body.Close()
		Expect(resp.StatusCode).To(Equal(http.StatusFound))
		loc := resp.Header.Get("Location")
		Expect(loc).To(ContainSubstring("code="))
		Expect(loc).To(ContainSubstring("state=s"))
	})

	It("token endpoint exchanges code for access token", func() {
		// Get code first
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		resp, err := client.Get(mock.URL() + "/oauth/authorize?client_id=x&response_type=code&redirect_uri=http://localhost/cb&state=s")
		Expect(err).ToNot(HaveOccurred())
		defer resp.Body.Close()
		Expect(resp.StatusCode).To(Equal(http.StatusFound))
		loc, err := resp.Location()
		Expect(err).ToNot(HaveOccurred())
		code := loc.Query().Get("code")
		Expect(code).ToNot(BeEmpty())

		// Exchange
		form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"x"}, "redirect_uri": {"http://localhost/cb"}}
		tokenResp, err := http.PostForm(mock.URL()+"/oauth/token", form)
		Expect(err).ToNot(HaveOccurred())
		defer tokenResp.Body.Close()
		Expect(tokenResp.StatusCode).To(Equal(http.StatusOK))
		body, _ := io.ReadAll(tokenResp.Body)
		Expect(string(body)).To(ContainSubstring("access_token"))
	})

	It("user info endpoint returns OpenShift user JSON", func() {
		resp, err := http.Get(mock.URL() + "/apis/user.openshift.io/v1/users/~")
		Expect(err).ToNot(HaveOccurred())
		defer resp.Body.Close()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		body, _ := io.ReadAll(resp.Body)
		Expect(string(body)).To(ContainSubstring("testuser"))
	})
})
