package header

import (
	"os"
	"path"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/logger"
)

var (
	filesDir string
)

func TestHeaderSuite(t *testing.T) {
	logger.SetOutput(GinkgoWriter)
	logger.SetErrOutput(GinkgoWriter)

	RegisterFailHandler(Fail)
	RunSpecs(t, "Header")
}

var _ = BeforeSuite(func() {
	os.Setenv("SECRET_ENV", "super-secret-env")

	dir, err := os.MkdirTemp("", "oauth2-proxy-header-suite")
	Expect(err).ToNot(HaveOccurred())
	Expect(os.WriteFile(path.Join(dir, "secret-file"), []byte("super-secret-file"), 0644)).To(Succeed())
	filesDir = dir
})

var _ = AfterSuite(func() {
	os.Unsetenv("SECRET_ENV")
	Expect(os.RemoveAll(filesDir)).To(Succeed())
})
