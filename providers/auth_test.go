package providers

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/sessions"
)

var authorizedAccessToken = "imaginary_access_token"

func CreateAuthorizedSession() *sessions.SessionState {
	return &sessions.SessionState{AccessToken: authorizedAccessToken}
}

func IsAuthorizedInHeader(reqHeader http.Header) bool {
	return IsAuthorizedInHeaderWithToken(reqHeader, authorizedAccessToken)
}

func IsAuthorizedInHeaderWithToken(reqHeader http.Header, token string) bool {
	return reqHeader.Get("Authorization") == fmt.Sprintf("Bearer %s", token)
}

func IsAuthorizedInURL(reqURL *url.URL) bool {
	return reqURL.Query().Get("access_token") == authorizedAccessToken
}
