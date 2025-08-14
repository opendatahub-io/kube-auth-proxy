package upstream

import (
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/options"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	middlewareapi "github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/middleware"
)

var _ = Describe("File Server Suite", func() {
	var dir string
	var handler http.Handler
	var id string

	const (
		foo          = "foo"
		bar          = "bar"
		baz          = "baz"
		pageNotFound = "404 page not found\n"
	)

	BeforeEach(func() {
		// Generate a random id before each test to check the GAP-Upstream-Address
		// is being set correctly
		idBytes := make([]byte, 16)
		_, err := io.ReadFull(rand.Reader, idBytes)
		Expect(err).ToNot(HaveOccurred())
		id = string(idBytes)
		upstream := options.Upstream{
			ID:   id,
			Path: "/files",
		}

		handler = newFileServer(upstream, filesDir)
	})

	AfterEach(func() {
		Expect(os.RemoveAll(dir)).To(Succeed())
	})

	DescribeTable("fileServer ServeHTTP",
		func(requestPath string, expectedResponseCode int, expectedBody string) {
			req := httptest.NewRequest("", requestPath, nil)
			req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{})

			rw := httptest.NewRecorder()
			handler.ServeHTTP(rw, req)

			scope := middlewareapi.GetRequestScope(req)
			Expect(scope.Upstream).To(Equal(id))

			Expect(rw.Code).To(Equal(expectedResponseCode))
			Expect(rw.Body.String()).To(Equal(expectedBody))
		},
		Entry("for file foo", "/files/foo", 200, foo),
		Entry("for file bar", "/files/bar", 200, bar),
		Entry("for file foo/baz", "/files/subdir/baz", 200, baz),
		Entry("for a non-existent file inside the path", "/files/baz", 404, pageNotFound),
		Entry("for a non-existent file oustide the path", "/baz", 404, pageNotFound),
	)
})
