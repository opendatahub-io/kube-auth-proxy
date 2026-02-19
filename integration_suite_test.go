//go:build integration

package main

import (
	"fmt"
	"net"
	"net/http/httptest"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/options"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/logger"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/validation"
)

func TestIntegrationSuite(t *testing.T) {
	logger.SetOutput(GinkgoWriter)
	logger.SetErrOutput(GinkgoWriter)
	RegisterFailHandler(Fail)
	RunSpecs(t, "Integration Suite")
}

// startProxyOnListener starts an httptest server on the given net.Listener and
// validates opts before creating the proxy. opts.RawRedirectURL must already
// contain the correct callback URL matching the listener's address.
func startProxyOnListener(opts *options.Options, ln net.Listener) *httptest.Server {
	Expect(validation.Validate(opts)).To(Succeed())
	proxy, err := NewOAuthProxy(opts, func(string) bool { return true }, nil)
	Expect(err).ToNot(HaveOccurred())

	server := httptest.NewUnstartedServer(proxy)
	server.Listener = ln
	server.Start()
	return server
}

// newFreePortListener allocates a listening socket on a free port and returns
// the listener and the URL (http://127.0.0.1:<port>).
func newFreePortListener() (net.Listener, string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	Expect(err).ToNot(HaveOccurred())
	port := ln.Addr().(*net.TCPAddr).Port
	return ln, fmt.Sprintf("http://127.0.0.1:%d", port)
}
