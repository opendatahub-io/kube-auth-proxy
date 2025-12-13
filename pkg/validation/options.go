package validation

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/mbland/hmacauth"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/apis/options"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/ip"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/logger"
	internaloidc "github.com/opendatahub-io/kube-auth-proxy/v1/pkg/providers/oidc"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/requests"
	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/util"
	"golang.org/x/oauth2"
)

const (
	// OpenShift authentication config API path
	authenticationConfigPath = "/apis/config.openshift.io/v1/authentications/cluster"
)

// Validate checks that required options are set and validates those that they
// are of the correct format
func Validate(o *options.Options) error {
	msgs := validateCookie(o.Cookie)
	msgs = append(msgs, validateSessionCookieMinimal(o)...)
	msgs = append(msgs, validateRedisSessionStore(o)...)
	msgs = append(msgs, prefixValues("injectRequestHeaders: ", validateHeaders(o.InjectRequestHeaders)...)...)
	msgs = append(msgs, prefixValues("injectResponseHeaders: ", validateHeaders(o.InjectResponseHeaders)...)...)
	msgs = append(msgs, validateProviders(o)...)
	msgs = append(msgs, validateAPIRoutes(o)...)
	msgs = configureLogger(o.Logging, msgs)
	msgs = parseSignatureKey(o, msgs)

	if o.SSLInsecureSkipVerify {
		transport := requests.DefaultTransport.(*http.Transport)
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- InsecureSkipVerify is a configurable option we allow
	} else if len(o.Providers[0].CAFiles) > 0 {
		pool, err := util.GetCertPool(o.Providers[0].CAFiles, o.Providers[0].UseSystemTrustStore)
		if err == nil {
			transport := requests.DefaultTransport.(*http.Transport)
			transport.TLSClientConfig = &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
			}
		} else {
			msgs = append(msgs, fmt.Sprintf("unable to load provider CA file(s): %v", err))
		}
	}

	if o.AuthenticatedEmailsFile == "" && len(o.EmailDomains) == 0 && o.HtpasswdFile == "" {
		msgs = append(msgs, "missing setting for email validation: email-domain or authenticated-emails-file required."+
			"\n      use email-domain=* to authorize all email addresses")
	}

	if o.TrustOpenShiftServiceAccountIssuer {
		issuer, err := discoverOpenShiftServiceAccountIssuer(
			o.Providers[0].CAFiles,
			o.Providers[0].UseSystemTrustStore,
			o.SSLInsecureSkipVerify,
		)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf(
				"failed to discover OpenShift service account issuer: %v", err))
		} else {
			logger.Printf("Auto-discovered OpenShift service account issuer: %s", issuer)
			o.ExtraJwtIssuers = append(o.ExtraJwtIssuers, issuer+"="+issuer)
			o.SkipJwtBearerTokens = true
		}
	}

	if o.SkipJwtBearerTokens && len(o.ExtraJwtIssuers) > 0 {
		// Auto-load service account CA for in-cluster JWKS fetching if no CA configured.
		// Skip if SSLInsecureSkipVerify is set or explicit CA files are provided.
		if !o.SSLInsecureSkipVerify && len(o.Providers[0].CAFiles) == 0 {
			if _, err := os.Stat(util.ServiceAccountCAPath); err == nil {
				pool, err := util.GetCertPool(
					[]string{util.ServiceAccountCAPath},
					o.Providers[0].UseSystemTrustStore,
				)
				if err == nil {
					transport := requests.DefaultTransport.(*http.Transport)
					transport.TLSClientConfig = &tls.Config{
						RootCAs:    pool,
						MinVersion: tls.VersionTLS12,
					}
					logger.Printf("Auto-loaded Kubernetes service account CA for JWT verification: %s",
						util.ServiceAccountCAPath)
				} else {
					logger.Printf("WARNING: Failed to load Kubernetes service account CA (%s): %v",
						util.ServiceAccountCAPath, err)
				}
			}
		}

		var jwtIssuers []jwtIssuer
		jwtIssuers, msgs = parseJwtIssuers(o.ExtraJwtIssuers, msgs)
		for _, jwtIssuer := range jwtIssuers {
			verifier, err := newVerifierFromJwtIssuer(
				o.Providers[0].OIDCConfig.AudienceClaims,
				o.Providers[0].OIDCConfig.ExtraAudiences,
				jwtIssuer,
			)
			if err != nil {
				msgs = append(msgs, fmt.Sprintf("error building verifiers: %s", err))
			}
			o.SetJWTBearerVerifiers(append(o.GetJWTBearerVerifiers(), verifier))
		}
	}

	var redirectURL *url.URL
	redirectURL, msgs = parseURL(o.RawRedirectURL, "redirect", msgs)
	o.SetRedirectURL(redirectURL)
	if o.RawRedirectURL == "" && !o.Cookie.Secure && !o.ReverseProxy {
		logger.Print("WARNING: no explicit redirect URL: redirects will default to insecure HTTP")
	}

	msgs = append(msgs, validateUpstreams(o.UpstreamServers)...)

	if o.ReverseProxy {
		parser, err := ip.GetRealClientIPParser(o.RealClientIPHeader)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("real_client_ip_header (%s) not accepted parameter value: %v", o.RealClientIPHeader, err))
		}
		o.SetRealClientIPParser(parser)

		// Allow the logger to get client IPs
		logger.SetGetClientFunc(func(r *http.Request) string {
			return ip.GetClientString(o.GetRealClientIPParser(), r, false)
		})
	}

	// Do this after ReverseProxy validation for TrustedIP coordinated checks
	msgs = append(msgs, validateAllowlists(o)...)

	if len(msgs) != 0 {
		return fmt.Errorf("invalid configuration:\n  %s",
			strings.Join(msgs, "\n  "))
	}
	return nil
}

func parseSignatureKey(o *options.Options, msgs []string) []string {
	if o.SignatureKey == "" {
		return msgs
	}

	logger.Print("WARNING: `--signature-key` is deprecated. It will be removed in a future release")

	components := strings.Split(o.SignatureKey, ":")
	if len(components) != 2 {
		return append(msgs, "invalid signature hash:key spec: "+
			o.SignatureKey)
	}

	algorithm, secretKey := components[0], components[1]
	hash, err := hmacauth.DigestNameToCryptoHash(algorithm)
	if err != nil {
		return append(msgs, "unsupported signature hash algorithm: "+o.SignatureKey)
	}
	o.SetSignatureData(&options.SignatureData{Hash: hash, Key: secretKey})
	return msgs
}

// parseJwtIssuers takes in an array of strings in the form of issuer=audience
// and parses to an array of jwtIssuer structs.
func parseJwtIssuers(issuers []string, msgs []string) ([]jwtIssuer, []string) {
	parsedIssuers := make([]jwtIssuer, 0, len(issuers))
	for _, jwtVerifier := range issuers {
		components := strings.Split(jwtVerifier, "=")
		if len(components) < 2 {
			msgs = append(msgs, fmt.Sprintf("invalid jwt verifier uri=audience spec: %s", jwtVerifier))
			continue
		}
		uri, audience := components[0], strings.Join(components[1:], "=")
		parsedIssuers = append(parsedIssuers, jwtIssuer{issuerURI: uri, audience: audience})
	}
	return parsedIssuers, msgs
}

// newVerifierFromJwtIssuer takes in issuer information in jwtIssuer info and returns
// a verifier for that issuer.
func newVerifierFromJwtIssuer(audienceClaims []string, extraAudiences []string, jwtIssuer jwtIssuer) (internaloidc.IDTokenVerifier, error) {
	pvOpts := internaloidc.ProviderVerifierOptions{
		AudienceClaims: audienceClaims,
		ClientID:       jwtIssuer.audience,
		ExtraAudiences: extraAudiences,
		IssuerURL:      jwtIssuer.issuerURI,
	}

	// Create a context with the configured HTTP client that has the proper CA certificates
	// This is required for the go-oidc library to use our TLS configuration when fetching JWKS
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, requests.DefaultHTTPClient)

	pv, err := internaloidc.NewProviderVerifier(ctx, pvOpts)
	if err != nil {
		// If the discovery didn't work, try again without discovery
		pvOpts.JWKsURL = strings.TrimSuffix(jwtIssuer.issuerURI, "/") + "/.well-known/jwks.json"
		pvOpts.SkipDiscovery = true

		pv, err = internaloidc.NewProviderVerifier(ctx, pvOpts)
		if err != nil {
			return nil, fmt.Errorf("could not construct provider verifier for JWT Issuer: %v", err)
		}
	}

	return pv.Verifier(), nil
}

// jwtIssuer hold parsed JWT issuer info that's used to construct a verifier.
type jwtIssuer struct {
	issuerURI string
	audience  string
}

// discoverOpenShiftServiceAccountIssuer fetches the service account issuer from
// the OpenShift authentication.config.openshift.io/cluster resource.
// If the issuer is not explicitly configured, it defaults to https://kubernetes.default.svc.
func discoverOpenShiftServiceAccountIssuer(caFiles []string, useSystemTrustStore, insecureSkipVerify bool) (string, error) {
	authConfigURL := util.GetKubernetesAPIURL(authenticationConfigPath)

	token, err := os.ReadFile(util.ServiceAccountTokenPath)
	if err != nil {
		return "", fmt.Errorf("failed to read service account token: %v", err)
	}

	client, err := util.NewKubernetesHTTPClient(caFiles, useSystemTrustStore, insecureSkipVerify)
	if err != nil {
		return "", fmt.Errorf("failed to create Kubernetes HTTP client: %v", err)
	}

	req, err := http.NewRequest("GET", authConfigURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch authentication config: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("authentication config request failed with status %d: %s",
			resp.StatusCode, string(body))
	}

	var authConfig struct {
		Spec struct {
			ServiceAccountIssuer string `json:"serviceAccountIssuer"`
		} `json:"spec"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&authConfig); err != nil {
		return "", fmt.Errorf("failed to parse authentication config: %v", err)
	}

	issuer := authConfig.Spec.ServiceAccountIssuer
	if issuer == "" {
		// Default to the in-cluster Kubernetes API server when not explicitly configured
		issuer = "https://kubernetes.default.svc"
	}

	return issuer, nil
}

func parseURL(toParse string, urltype string, msgs []string) (*url.URL, []string) {
	parsed, err := url.Parse(toParse)
	if err != nil {
		return nil, append(msgs, fmt.Sprintf(
			"error parsing %s-url=%q %s", urltype, toParse, err))
	}
	return parsed, msgs
}
