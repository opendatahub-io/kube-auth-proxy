package http

import (
	"crypto/tls"
	"os"
	"testing"

	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/options"
	"k8s.io/client-go/util/cert"
)

func TestNewServerAppliesCurvePreferencesToTLSListener(t *testing.T) {
	tmpDir := t.TempDir()
	certBytes, keyBytes, err := cert.GenerateSelfSignedCertKey("localhost", nil, nil)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCertKey() returned an error: %v", err)
	}
	certPath := tmpDir + "/tls.crt"
	keyPath := tmpDir + "/tls.key"
	if err := os.WriteFile(certPath, certBytes, 0600); err != nil {
		t.Fatalf("writing certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, keyBytes, 0600); err != nil {
		t.Fatalf("writing key: %v", err)
	}

	createdServer, err := NewServer(Opts{
		SecureBindAddress: "127.0.0.1:0",
		TLS: &options.TLS{
			Cert:             &options.SecretSource{FromFile: certPath},
			Key:              &options.SecretSource{FromFile: keyPath},
			CurvePreferences: []string{"23", "4588"},
		},
	})
	if err != nil {
		t.Fatalf("NewServer() returned an error: %v", err)
	}
	defer createdServer.(*server).tlsListener.Close()

	config := createdServer.(*server).tlsConfig
	if len(config.CurvePreferences) != 2 {
		t.Fatalf("CurvePreferences = %v, want two configured groups", config.CurvePreferences)
	}
	if config.CurvePreferences[0] != tls.CurveP256 || config.CurvePreferences[1] != tls.X25519MLKEM768 {
		t.Errorf("CurvePreferences = %v, want P-256 and X25519MLKEM768", config.CurvePreferences)
	}
}
