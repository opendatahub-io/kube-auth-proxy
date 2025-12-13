package validation

import (
	"crypto"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/options"
	"github.com/stretchr/testify/assert"
)

const (
	cookieSecret = "secretthirtytwobytes+abcdefghijk"
	clientID     = "bazquux"
	clientSecret = "xyzzyplugh"
	providerID   = "providerID"
)

func testOptions() *options.Options {
	o := options.NewOptions()
	o.UpstreamServers.Upstreams = append(o.UpstreamServers.Upstreams, options.Upstream{
		ID:   "upstream",
		Path: "/",
		URI:  "http://127.0.0.1:8080/",
	})
	o.Cookie.Secret = cookieSecret
	o.Providers[0].ID = providerID
	o.Providers[0].ClientID = clientID
	o.Providers[0].ClientSecret = clientSecret
	o.EmailDomains = []string{"*"}
	return o
}

func errorMsg(msgs []string) string {
	result := make([]string, 0)
	result = append(result, "invalid configuration:")
	result = append(result, msgs...)
	return strings.Join(result, "\n  ")
}

func TestNewOptions(t *testing.T) {
	o := options.NewOptions()
	o.EmailDomains = []string{"*"}
	err := Validate(o)
	assert.NotEqual(t, nil, err)

	expected := errorMsg([]string{
		"missing setting: cookie-secret or cookie-secret-file",
		"provider has empty id: ids are required for all providers",
		"provider missing setting: client-id",
		"missing setting: client-secret or client-secret-file"})
	assert.Equal(t, expected, err.Error())
}

func TestInitializedOptions(t *testing.T) {
	o := testOptions()
	assert.Equal(t, nil, Validate(o))
}

// Note that it's not worth testing nonparseable URLs, since url.Parse()
// seems to parse damn near anything.
func TestRedirectURL(t *testing.T) {
	o := testOptions()
	o.RawRedirectURL = "https://myhost.com/oauth2/callback"
	assert.Equal(t, nil, Validate(o))
	expected := &url.URL{
		Scheme: "https", Host: "myhost.com", Path: "/oauth2/callback"}
	assert.Equal(t, expected, o.GetRedirectURL())
}

func TestCookieRefreshMustBeLessThanCookieExpire(t *testing.T) {
	o := testOptions()
	assert.Equal(t, nil, Validate(o))

	o.Cookie.Secret = "0123456789abcdef"
	o.Cookie.Refresh = o.Cookie.Expire
	assert.NotEqual(t, nil, Validate(o))

	o.Cookie.Refresh -= time.Duration(1)
	assert.Equal(t, nil, Validate(o))
}

func TestBase64CookieSecret(t *testing.T) {
	o := testOptions()
	assert.Equal(t, nil, Validate(o))

	// 32 byte, base64 (urlsafe) encoded key
	o.Cookie.Secret = "yHBw2lh2Cvo6aI_jn_qMTr-pRAjtq0nzVgDJNb36jgQ="
	assert.Equal(t, nil, Validate(o))

	// 32 byte, base64 (urlsafe) encoded key, w/o padding
	o.Cookie.Secret = "yHBw2lh2Cvo6aI_jn_qMTr-pRAjtq0nzVgDJNb36jgQ"
	assert.Equal(t, nil, Validate(o))

	// 24 byte, base64 (urlsafe) encoded key
	o.Cookie.Secret = "Kp33Gj-GQmYtz4zZUyUDdqQKx5_Hgkv3"
	assert.Equal(t, nil, Validate(o))

	// 16 byte, base64 (urlsafe) encoded key
	o.Cookie.Secret = "LFEqZYvYUwKwzn0tEuTpLA=="
	assert.Equal(t, nil, Validate(o))

	// 16 byte, base64 (urlsafe) encoded key, w/o padding
	o.Cookie.Secret = "LFEqZYvYUwKwzn0tEuTpLA"
	assert.Equal(t, nil, Validate(o))
}

func TestValidateSignatureKey(t *testing.T) {
	o := testOptions()
	o.SignatureKey = "sha1:secret"
	assert.Equal(t, nil, Validate(o))
	assert.Equal(t, o.GetSignatureData().Hash, crypto.SHA1)
	assert.Equal(t, o.GetSignatureData().Key, "secret")
}

func TestValidateSignatureKeyInvalidSpec(t *testing.T) {
	o := testOptions()
	o.SignatureKey = "invalid spec"
	err := Validate(o)
	assert.Equal(t, err.Error(), "invalid configuration:\n"+
		"  invalid signature hash:key spec: "+o.SignatureKey)
}

func TestValidateSignatureKeyUnsupportedAlgorithm(t *testing.T) {
	o := testOptions()
	o.SignatureKey = "unsupported:default secret"
	err := Validate(o)
	assert.Equal(t, err.Error(), "invalid configuration:\n"+
		"  unsupported signature hash algorithm: "+o.SignatureKey)
}

func TestGCPHealthcheck(t *testing.T) {
	o := testOptions()
	o.GCPHealthChecks = true
	assert.Equal(t, nil, Validate(o))
}

func TestRealClientIPHeader(t *testing.T) {
	// Ensure nil if ReverseProxy not set.
	o := testOptions()
	o.RealClientIPHeader = "X-Real-IP"
	assert.Equal(t, nil, Validate(o))
	assert.Nil(t, o.GetRealClientIPParser())

	// Ensure simple use case works.
	o = testOptions()
	o.ReverseProxy = true
	o.RealClientIPHeader = "X-Forwarded-For"
	assert.Equal(t, nil, Validate(o))
	assert.NotNil(t, o.GetRealClientIPParser())

	// Ensure unknown header format process an error.
	o = testOptions()
	o.ReverseProxy = true
	o.RealClientIPHeader = "Forwarded"
	err := Validate(o)
	assert.NotEqual(t, nil, err)
	expected := errorMsg([]string{
		"real_client_ip_header (Forwarded) not accepted parameter value: the http header key (Forwarded) is either invalid or unsupported",
	})
	assert.Equal(t, expected, err.Error())
	assert.Nil(t, o.GetRealClientIPParser())

	// Ensure invalid header format produces an error.
	o = testOptions()
	o.ReverseProxy = true
	o.RealClientIPHeader = "!934invalidheader-23:"
	err = Validate(o)
	assert.NotEqual(t, nil, err)
	expected = errorMsg([]string{
		"real_client_ip_header (!934invalidheader-23:) not accepted parameter value: the http header key (!934invalidheader-23:) is either invalid or unsupported",
	})
	assert.Equal(t, expected, err.Error())
	assert.Nil(t, o.GetRealClientIPParser())
}

func TestProviderCAFilesError(t *testing.T) {
	file, err := os.CreateTemp("", "absent.*.crt")
	assert.NoError(t, err)
	assert.NoError(t, file.Close())
	assert.NoError(t, os.Remove(file.Name()))

	o := testOptions()
	o.Providers[0].CAFiles = append(o.Providers[0].CAFiles, file.Name())
	err = Validate(o)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to load provider CA file(s)")
}

func TestValidationWithoutJWTIssuersDoesNotRequireServiceAccountCA(t *testing.T) {
	o := testOptions()

	err := Validate(o)
	assert.NoError(t, err)
}

func TestValidationWithSkipJwtBearerTokensButNoIssuers(t *testing.T) {
	o := testOptions()
	o.SkipJwtBearerTokens = true

	err := Validate(o)
	assert.NoError(t, err)
}

func TestValidationWithExplicitCAFilesSkipsServiceAccountCAAutoLoad(t *testing.T) {
	caFile, err := os.CreateTemp("", "ca.*.crt")
	assert.NoError(t, err)
	defer os.Remove(caFile.Name())

	dummyCert := `-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4P2DxFzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
o5e7CnJzr7jHGxqJLGHZDkWaOQwFv8nG0FHjqZgucuCKv7wWHrHC6VvpH8R8fNlS
GqZTCcRTgGjJ9JQ9l7eFNi0S6J5J9xM+FuLRdJBJ8l6x+Qs0qlYFqbELdGQTZjPk
pQ5tKlvj5N7TvGq/+HlbQfnvGzl6k1aNnT3cOP0FlHrB/kKYw5n8cP0BPPBLdIfH
jXpT0dZWRbWKmBnp5nSA+B/YbC2bfG7xmJJrgQwPosrfB6nnD/AE6rJf8EYFNwB7
lM6tAd9zC5cQoQfQ4Mg7+mFqPRGW7cj0nBvFn1yvYRlh0n1kkjVGpYTzq3jHHEuF
0lPB5GG9Y6P/n0bL7q6vAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAKIsTw/px+AR
RkP5+PBr4wOTxH8ROLPY9Ec/wgVDZMH5j7H0jgAAy1SY0zCTvKwmHvBr6SY0+/TV
Y+rTzKjLNckv1Y8vRVbJ1N3d7nL5G8nuAHBr7J4oDg5g6RB0EULRvf6n1Js8rl1N
cE8bVvSvBLWytJzY1GqHA/VdRv0B/z+w/r5r+ajT1UEZU5AHKhDjJR2Y/BLHXriL
rJDznp1LL9RkXL8L+HPKI5x2Pj6BL/xXFN0FVjB2AhYun0Y+bjFrC4cNyWOCmwVA
hNgL+YR8eE5t0nlfSrpjIJsT0KC/wj1D7PEjzXMH4PPzzeSa4YPPF7h2Jrz8R7v/
7E8ouS3gzj0=
-----END CERTIFICATE-----`
	_, err = caFile.WriteString(dummyCert)
	assert.NoError(t, err)
	assert.NoError(t, caFile.Close())

	o := testOptions()
	o.Providers[0].CAFiles = []string{caFile.Name()}
	o.SkipJwtBearerTokens = true

	err = Validate(o)
	assert.NoError(t, err)
}
