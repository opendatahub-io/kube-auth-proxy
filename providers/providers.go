package providers

import (
	"context"
	"fmt"
	"net/url"

	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/options"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/sessions"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/logger"
	internaloidc "github.com/opendatahub-io/kube-auth-proxy/v1/pkg/providers/oidc"
	k8serrors "k8s.io/apimachinery/pkg/util/errors"
)

const (
	CodeChallengeMethodPlain = "plain"
	CodeChallengeMethodS256  = "S256"
)

// Provider represents an upstream identity provider implementation
type Provider interface {
	Data() *ProviderData
	GetLoginURL(redirectURI, finalRedirect, nonce string, extraParams url.Values) string
	Redeem(ctx context.Context, redirectURI, code, codeVerifier string) (*sessions.SessionState, error)
	// Deprecated: Migrate to EnrichSession
	GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error)
	EnrichSession(ctx context.Context, s *sessions.SessionState) error
	Authorize(ctx context.Context, s *sessions.SessionState) (bool, error)
	ValidateSession(ctx context.Context, s *sessions.SessionState) bool
	RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error)
	CreateSessionFromToken(ctx context.Context, token string) (*sessions.SessionState, error)
}

func NewProvider(providerConfig options.Provider) (Provider, error) {
	providerData, err := newProviderDataFromConfig(providerConfig)
	if err != nil {
		return nil, fmt.Errorf("could not create provider data: %v", err)
	}
	switch providerConfig.Type {
	case options.OIDCProvider:
		return NewOIDCProvider(providerData, providerConfig.OIDCConfig), nil
	case options.OpenShiftProvider:
		return NewOpenShiftProvider(providerData, providerConfig)
	default:
		return nil, fmt.Errorf("unknown provider type %q", providerConfig.Type)
	}
}

func newProviderDataFromConfig(providerConfig options.Provider) (*ProviderData, error) {
	p := &ProviderData{
		ProviderName:            providerConfig.Name,
		Scope:                   providerConfig.Scope,
		ClientID:                providerConfig.ClientID,
		ClientSecret:            providerConfig.ClientSecret,
		ClientSecretFile:        providerConfig.ClientSecretFile,
		AuthRequestResponseMode: providerConfig.AuthRequestResponseMode,
	}

	needsVerifier, err := providerRequiresOIDCProviderVerifier(providerConfig.Type)
	if err != nil {
		return nil, err
	}

	if needsVerifier {
		pv, err := internaloidc.NewProviderVerifier(context.TODO(), internaloidc.ProviderVerifierOptions{
			AudienceClaims:         providerConfig.OIDCConfig.AudienceClaims,
			ClientID:               providerConfig.ClientID,
			ExtraAudiences:         providerConfig.OIDCConfig.ExtraAudiences,
			IssuerURL:              providerConfig.OIDCConfig.IssuerURL,
			JWKsURL:                providerConfig.OIDCConfig.JwksURL,
			PublicKeyFiles:         providerConfig.OIDCConfig.PublicKeyFiles,
			SkipDiscovery:          providerConfig.OIDCConfig.SkipDiscovery,
			SkipIssuerVerification: providerConfig.OIDCConfig.InsecureSkipIssuerVerification,
		})
		if err != nil {
			return nil, fmt.Errorf("error building OIDC ProviderVerifier: %v", err)
		}

		p.Verifier = pv.Verifier()
		if pv.DiscoveryEnabled() {
			// Use the discovered values rather than any specified values
			endpoints := pv.Provider().Endpoints()
			pkce := pv.Provider().PKCE()
			providerConfig.LoginURL = endpoints.AuthURL
			providerConfig.RedeemURL = endpoints.TokenURL
			providerConfig.ProfileURL = endpoints.UserInfoURL
			providerConfig.OIDCConfig.JwksURL = endpoints.JWKsURL
			p.SupportedCodeChallengeMethods = pkce.CodeChallengeAlgs
		}
	}

	errs := []error{}
	for name, u := range map[string]struct {
		dst **url.URL
		raw string
	}{
		"login":    {dst: &p.LoginURL, raw: providerConfig.LoginURL},
		"redeem":   {dst: &p.RedeemURL, raw: providerConfig.RedeemURL},
		"profile":  {dst: &p.ProfileURL, raw: providerConfig.ProfileURL},
		"validate": {dst: &p.ValidateURL, raw: providerConfig.ValidateURL},
		"resource": {dst: &p.ProtectedResource, raw: providerConfig.ProtectedResource},
	} {
		var err error
		*u.dst, err = url.Parse(u.raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("could not parse %s URL: %v", name, err))
		}
	}
	// handle LoginURLParameters
	errs = append(errs, p.compileLoginParams(providerConfig.LoginURLParameters)...)

	if len(errs) > 0 {
		return nil, k8serrors.NewAggregate(errs)
	}

	// Make the OIDC options available to all providers that support it
	p.AllowUnverifiedEmail = providerConfig.OIDCConfig.InsecureAllowUnverifiedEmail
	p.EmailClaim = providerConfig.OIDCConfig.EmailClaim
	p.GroupsClaim = providerConfig.OIDCConfig.GroupsClaim
	p.SkipClaimsFromProfileURL = providerConfig.SkipClaimsFromProfileURL

	// Set PKCE enabled or disabled based on discovery and force options
	p.CodeChallengeMethod = parseCodeChallengeMethod(providerConfig)
	if len(p.SupportedCodeChallengeMethods) != 0 && p.CodeChallengeMethod == "" {
		logger.Printf("Warning: Your provider supports PKCE methods %+q, but you have not enabled one with --code-challenge-method", p.SupportedCodeChallengeMethods)
	}

	if providerConfig.OIDCConfig.UserIDClaim == "" {
		providerConfig.OIDCConfig.UserIDClaim = "email"
	}

	// TODO (@NickMeves) - Remove This
	// Backwards Compatibility for Deprecated UserIDClaim option
	if providerConfig.OIDCConfig.EmailClaim == options.OIDCEmailClaim &&
		providerConfig.OIDCConfig.UserIDClaim != options.OIDCEmailClaim {
		p.EmailClaim = providerConfig.OIDCConfig.UserIDClaim
	}

	p.setAllowedGroups(providerConfig.AllowedGroups)

	p.BackendLogoutURL = providerConfig.BackendLogoutURL

	return p, nil
}

// Pick the most appropriate code challenge method for PKCE
// At this time we do not consider what the server supports to be safe and
// only enable PKCE if the user opts-in
func parseCodeChallengeMethod(providerConfig options.Provider) string {
	switch {
	case providerConfig.CodeChallengeMethod != "":
		return providerConfig.CodeChallengeMethod
	default:
		return ""
	}
}

func providerRequiresOIDCProviderVerifier(providerType options.ProviderType) (bool, error) {
	switch providerType {
	case options.OIDCProvider:
		return true, nil
	case options.OpenShiftProvider:
		return false, nil
	default:
		return false, fmt.Errorf("unknown provider type: %s", providerType)
	}
}
