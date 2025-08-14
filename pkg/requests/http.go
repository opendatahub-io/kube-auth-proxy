package requests

import (
	"net/http"

	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/version"
)

type userAgentTransport struct {
	next      http.RoundTripper
	userAgent string
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	setDefaultUserAgent(r.Header, t.userAgent)
	return t.next.RoundTrip(r)
}

var DefaultHTTPClient = &http.Client{Transport: &userAgentTransport{
	next:      DefaultTransport,
	userAgent: "kube-auth-proxy/" + version.VERSION,
}}

var DefaultTransport = http.DefaultTransport

func setDefaultUserAgent(header http.Header, userAgent string) {
	if header != nil && len(header.Values("User-Agent")) == 0 {
		header.Set("User-Agent", userAgent)
	}
}
