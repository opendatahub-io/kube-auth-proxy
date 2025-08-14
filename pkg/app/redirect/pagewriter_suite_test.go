package redirect

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/logger"
)

func TestOptionsSuite(t *testing.T) {
	logger.SetOutput(GinkgoWriter)
	logger.SetErrOutput(GinkgoWriter)

	RegisterFailHandler(Fail)
	RunSpecs(t, "Redirect Suite")
}

// testValidator creates a mock validator that will always return the given result.
func testValidator(result bool, allowedRedirects ...string) Validator {
	return &mockValidator{result: result, allowedRedirects: allowedRedirects}
}

// mockValidator implements the Validator interface for use in testing.
type mockValidator struct {
	result           bool
	allowedRedirects []string
}

// IsValidRedirect implements the Validator interface.
func (m *mockValidator) IsValidRedirect(redirect string) bool {
	for _, allowed := range m.allowedRedirects {
		if redirect == allowed {
			return true
		}
	}

	return m.result
}
