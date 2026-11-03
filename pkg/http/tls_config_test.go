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

func TestTLSVersion(t *testing.T) {
	tests := []struct {
		name        string
		versionName string
		want        uint16
		wantErr     bool
	}{
		{name: "go name TLS 1.0", versionName: goTLSVersion10, want: tls.VersionTLS10},
		{name: "go name TLS 1.1", versionName: goTLSVersion11, want: tls.VersionTLS11},
		{name: "go name TLS 1.2", versionName: goTLSVersion12, want: tls.VersionTLS12},
		{name: "go name TLS 1.3", versionName: goTLSVersion13, want: tls.VersionTLS13},
		{name: "short-form TLS 1.0", versionName: shortTLSVersion10, want: tls.VersionTLS10},
		{name: "short-form TLS 1.1", versionName: shortTLSVersion11, want: tls.VersionTLS11},
		{name: "short-form TLS 1.2", versionName: shortTLSVersion12, want: tls.VersionTLS12},
		{name: "short-form TLS 1.3", versionName: shortTLSVersion13, want: tls.VersionTLS13},
		{name: "unknown version", versionName: "TLS1.4", wantErr: true},
		{name: "empty version", versionName: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tlsVersion(tt.versionName)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("tlsVersion(%q) = %d, want error", tt.versionName, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("tlsVersion(%q) returned an error: %v", tt.versionName, err)
			}
			if got != tt.want {
				t.Errorf("tlsVersion(%q) = %#x, want %#x", tt.versionName, got, tt.want)
			}
		})
	}
}

func TestNewServerAppliesMinVersionToTLSListener(t *testing.T) {
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

	// The configured minimum is honored exactly, including TLS 1.0 for the
	// Old cluster profile: Go 1.22+ defaults the server minimum to TLS 1.2
	// only when tls.Config.MinVersion is unset.
	createdServer, err := NewServer(Opts{
		SecureBindAddress: "127.0.0.1:0",
		TLS: &options.TLS{
			Cert:       &options.SecretSource{FromFile: certPath},
			Key:        &options.SecretSource{FromFile: keyPath},
			MinVersion: shortTLSVersion10,
		},
	})
	if err != nil {
		t.Fatalf("NewServer() returned an error: %v", err)
	}
	defer createdServer.(*server).tlsListener.Close()

	config := createdServer.(*server).tlsConfig
	if config.MinVersion != tls.VersionTLS10 {
		t.Errorf("MinVersion = %#x, want TLS 1.0 honored exactly", config.MinVersion)
	}

	if _, err := NewServer(Opts{
		SecureBindAddress: "127.0.0.1:0",
		TLS: &options.TLS{
			Cert:       &options.SecretSource{FromFile: certPath},
			Key:        &options.SecretSource{FromFile: keyPath},
			MinVersion: "TLS2.0",
		},
	}); err == nil {
		t.Error("NewServer() with an unknown MinVersion = nil error, want error")
	}
}
