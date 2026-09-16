package tls

import (
	cryptotls "crypto/tls"
	"errors"
	"reflect"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"k8s.io/client-go/rest"
)

func TestShouldUsePortableDefaults(t *testing.T) {
	if !shouldUsePortableDefaults("", rest.ErrNotInCluster) {
		t.Fatal("expected ErrNotInCluster without kubeconfig to use portable defaults")
	}
	if shouldUsePortableDefaults("", errors.New("service account token is unreadable")) {
		t.Fatal("unexpected errors must not use portable defaults")
	}
	if shouldUsePortableDefaults("/tmp/config", rest.ErrNotInCluster) {
		t.Fatal("explicit kubeconfig errors must not use portable defaults")
	}
}

func TestTLSOptsPreservesOldAndCustomTLSVersions(t *testing.T) {
	tests := []struct {
		name    string
		profile configv1.TLSProfileSpec
		want    uint16
	}{
		{
			name:    "Old",
			profile: *configv1.TLSProfiles[configv1.TLSProfileOldType],
			want:    cryptotls.VersionTLS10,
		},
		{
			name: "Custom TLS 1.1",
			profile: configv1.TLSProfileSpec{
				MinTLSVersion: configv1.VersionTLS11,
			},
			want: cryptotls.VersionTLS11,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options, err := tlsOpts(test.profile)
			if err != nil {
				t.Fatalf("tlsOpts() returned an error: %v", err)
			}
			config := &cryptotls.Config{}
			for _, option := range options {
				option(config)
			}
			if config.MinVersion != test.want {
				t.Fatalf("MinVersion = %d, want %d", config.MinVersion, test.want)
			}
		})
	}
}

func TestTLSOptsMapsOldCiphersAndGroups(t *testing.T) {
	profile := *configv1.TLSProfiles[configv1.TLSProfileOldType]
	profile.Groups = []configv1.TLSGroup{
		configv1.TLSGroupX25519,
		configv1.TLSGroupX25519MLKEM768,
		configv1.TLSGroupSecP256r1MLKEM768,
	}

	options, err := tlsOpts(profile)
	if err != nil {
		t.Fatalf("tlsOpts() returned an error: %v", err)
	}
	config := &cryptotls.Config{}
	for _, option := range options {
		option(config)
	}
	if len(config.CipherSuites) == 0 {
		t.Fatal("CipherSuites is empty for the Old profile")
	}
	wantGroups := []cryptotls.CurveID{
		cryptotls.X25519,
		cryptotls.X25519MLKEM768,
		cryptotls.SecP256r1MLKEM768,
	}
	if !reflect.DeepEqual(config.CurvePreferences, wantGroups) {
		t.Fatalf("CurvePreferences = %v, want %v", config.CurvePreferences, wantGroups)
	}
}

func TestStrictProfileRejectsMalformedValues(t *testing.T) {
	if _, err := profileSpec(&configv1.TLSSecurityProfile{Type: configv1.TLSProfileCustomType}); err == nil {
		t.Fatal("profileSpec() accepted a Custom profile without Custom settings")
	}
	if _, err := tlsOpts(configv1.TLSProfileSpec{}); err == nil {
		t.Fatal("tlsOpts() accepted an empty minimum TLS version")
	}
	if shouldHonorProfile(configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly) {
		t.Fatal("legacy adherence should not honor the cluster profile")
	}
	if !shouldHonorProfile(configv1.TLSAdherencePolicy("future")) {
		t.Fatal("unknown adherence should be treated as Strict")
	}
}
