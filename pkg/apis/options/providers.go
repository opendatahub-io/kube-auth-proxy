package options

const (
	// OIDCEmailClaim is the generic email claim used by the OIDC provider.
	OIDCEmailClaim = "email"

	// OIDCGroupsClaim is the generic groups claim used by the OIDC provider.
	OIDCGroupsClaim = "groups"

	// ClaimAccessToken is the claim name for access tokens.
	ClaimAccessToken = "access_token"

	// ClaimIDToken is the claim name for ID tokens.
	ClaimIDToken = "id_token"

	// ClaimPreferredUsername is the claim name for the preferred username.
	ClaimPreferredUsername = "preferred_username"

	// ClaimUser is the claim name for the user identifier.
	ClaimUser = "user"

	// ClaimAud is the audience claim name.
	ClaimAud = "aud"
)

// OIDCAudienceClaims is the generic audience claim list used by the OIDC provider.
var OIDCAudienceClaims = []string{ClaimAud}

// The provider can be selected using the `provider` configuration value, or
// set in the [`providers` array using
// AlphaConfig](https://oauth2-proxy.github.io/oauth2-proxy/configuration/alpha-config#providers).
// However, [**the feature to implement multiple providers is not
// complete**](https://github.com/oauth2-proxy/oauth2-proxy/issues/926).
type Providers []Provider

// Provider holds all configuration for a single provider
type Provider struct {
	// ClientID is the OAuth Client ID that is defined in the provider
	// This value is required for all providers.
	ClientID string `json:"clientID,omitempty"`
	// ClientSecret is the OAuth Client Secret that is defined in the provider
	// This value is required for all providers.
	ClientSecret string `json:"clientSecret,omitempty"`
	// ClientSecretFile is the name of the file
	// containing the OAuth Client Secret, it will be used if ClientSecret is not set.
	ClientSecretFile string `json:"clientSecretFile,omitempty"`

	// OIDCConfig holds all configurations for OIDC provider
	// or providers utilize OIDC configurations.
	OIDCConfig OIDCOptions `json:"oidcConfig,omitempty"`

	// ID should be a unique identifier for the provider.
	// This value is required for all providers.
	ID string `json:"id,omitempty"`
	// Type is the OAuth provider
	// must be set from the supported providers group,
	// otherwise 'Google' is set as default
	Type ProviderType `json:"provider,omitempty"`
	// Name is the providers display name
	// if set, it will be shown to the users in the login page.
	Name string `json:"name,omitempty"`
	// CAFiles is a list of paths to CA certificates that should be used when connecting to the provider.
	// If not specified, the default Go trust sources are used instead
	CAFiles []string `json:"caFiles,omitempty"`
	// UseSystemTrustStore determines if your custom CA files and the system trust store are used
	// If set to true, your custom CA files and the system trust store are used otherwise only your custom CA files.
	UseSystemTrustStore bool `json:"useSystemTrustStore,omitempty"`
	// LoginURL is the authentication endpoint
	LoginURL string `json:"loginURL,omitempty"`
	// LoginURLParameters defines the parameters that can be passed from the start URL to the IdP login URL
	LoginURLParameters []LoginURLParameter `json:"loginURLParameters,omitempty"`
	// AuthRequestResponseMode defines the response mode to request during authorization request
	AuthRequestResponseMode string `json:"authRequestResponseMode,omitempty"`
	// RedeemURL is the token redemption endpoint
	RedeemURL string `json:"redeemURL,omitempty"`
	// ProfileURL is the profile access endpoint
	ProfileURL string `json:"profileURL,omitempty"`
	// SkipClaimsFromProfileURL allows to skip request to Profile URL for resolving claims not present in id_token
	// default set to 'false'
	SkipClaimsFromProfileURL bool `json:"skipClaimsFromProfileURL,omitempty"`
	// ProtectedResource is the resource that is protected (Azure AD and ADFS only)
	ProtectedResource string `json:"resource,omitempty"`
	// ValidateURL is the access token validation endpoint
	ValidateURL string `json:"validateURL,omitempty"`
	// Scope is the OAuth scope specification
	Scope string `json:"scope,omitempty"`
	// AllowedGroups is a list of restrict logins to members of this group
	AllowedGroups []string `json:"allowedGroups,omitempty"`
	// The code challenge method
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`

	// URL to call to perform backend logout, `{id_token}` would be replaced by the actual `id_token` if available in the session
	BackendLogoutURL string `json:"backendLogoutURL"`

	// OpenShift-specific options
	// ServiceAccount is the name of the OpenShift service account to use for auto-detecting OAuth client credentials
	ServiceAccount string `json:"serviceAccount,omitempty"`
}

// ProviderType is used to enumerate the different provider type options
// Valid options are: oidc.
type ProviderType string

const (
	// OIDCProvider is the provider type for OIDC
	OIDCProvider ProviderType = "oidc"
	// OpenShiftProvider is the provider type for OpenShift OAuth
	OpenShiftProvider ProviderType = "openshift"
)

type OIDCOptions struct {
	// IssuerURL is the OpenID Connect issuer URL
	// eg: https://accounts.google.com
	IssuerURL string `json:"issuerURL,omitempty"`
	// InsecureAllowUnverifiedEmail prevents failures if an email address in an id_token is not verified
	// default set to 'false'
	InsecureAllowUnverifiedEmail bool `json:"insecureAllowUnverifiedEmail,omitempty"`
	// InsecureSkipIssuerVerification skips verification of ID token issuers. When false, ID Token Issuers must match the OIDC discovery URL
	// default set to 'false'
	InsecureSkipIssuerVerification bool `json:"insecureSkipIssuerVerification,omitempty"`
	// InsecureSkipNonce skips verifying the ID Token's nonce claim that must match
	// the random nonce sent in the initial OAuth flow. Otherwise, the nonce is checked
	// after the initial OAuth redeem & subsequent token refreshes.
	// default set to 'true'
	// Warning: In a future release, this will change to 'false' by default for enhanced security.
	InsecureSkipNonce bool `json:"insecureSkipNonce,omitempty"`
	// SkipDiscovery allows to skip OIDC discovery and use manually supplied Endpoints
	// default set to 'false'
	SkipDiscovery bool `json:"skipDiscovery,omitempty"`
	// JwksURL is the OpenID Connect JWKS URL
	// eg: https://www.googleapis.com/oauth2/v3/certs
	JwksURL string `json:"jwksURL,omitempty"`
	// PublicKeyFiles is a list of paths pointing to public key files in PEM format to use
	// for verifying JWT tokens
	PublicKeyFiles []string `json:"publicKeyFiles,omitempty"`
	// EmailClaim indicates which claim contains the user email,
	// default set to 'email'
	EmailClaim string `json:"emailClaim,omitempty"`
	// GroupsClaim indicates which claim contains the user groups
	// default set to 'groups'
	GroupsClaim string `json:"groupsClaim,omitempty"`
	// UserIDClaim indicates which claim contains the user ID
	// default set to 'email'
	UserIDClaim string `json:"userIDClaim,omitempty"`
	// AudienceClaim allows to define any claim that is verified against the client id
	// By default `aud` claim is used for verification.
	AudienceClaims []string `json:"audienceClaims,omitempty"`
	// ExtraAudiences is a list of additional audiences that are allowed
	// to pass verification in addition to the client id.
	ExtraAudiences []string `json:"extraAudiences,omitempty"`
}

func providerDefaults() Providers {
	providers := Providers{
		{
			Type: OIDCProvider,
			OIDCConfig: OIDCOptions{
				InsecureAllowUnverifiedEmail: false,
				InsecureSkipNonce:            true,
				SkipDiscovery:                false,
				UserIDClaim:                  OIDCEmailClaim, // Deprecated: Use OIDCEmailClaim
				EmailClaim:                   OIDCEmailClaim,
				GroupsClaim:                  OIDCGroupsClaim,
				AudienceClaims:               OIDCAudienceClaims,
				ExtraAudiences:               []string{},
			},
		},
	}
	return providers
}
