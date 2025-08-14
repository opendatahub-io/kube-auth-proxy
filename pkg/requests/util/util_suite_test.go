package util_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/logger"
)

// TestRequestUtilSuite and related tests are in a *_test package
// to prevent circular imports with the `logger` package which uses
// this functionality
func TestRequestUtilSuite(t *testing.T) {
	logger.SetOutput(GinkgoWriter)
	logger.SetErrOutput(GinkgoWriter)

	RegisterFailHandler(Fail)
	RunSpecs(t, "Request Utils")
}
