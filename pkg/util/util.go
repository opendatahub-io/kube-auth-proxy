package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func GetCertPool(paths []string, useSystemPool bool) (*x509.CertPool, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("invalid empty list of Root CAs file paths")
	}

	var pool *x509.CertPool
	if useSystemPool {
		rootPool, err := getSystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("unable to get SystemCertPool when append is true - #{err}")
		}
		pool = rootPool
	} else {
		pool = x509.NewCertPool()
	}

	return loadCertsFromPaths(paths, pool)

}

func getSystemCertPool() (*x509.CertPool, error) {
	rootPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	if rootPool == nil {
		return nil, fmt.Errorf("SystemCertPool is empty")
	}

	return rootPool, nil
}

func loadCertsFromPaths(paths []string, pool *x509.CertPool) (*x509.CertPool, error) {
	for _, path := range paths {
		// Cert paths are a configurable option
		data, err := os.ReadFile(path) // #nosec G304
		if err != nil {
			return nil, fmt.Errorf("certificate authority file (%s) could not be read - %s", path, err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("loading certificate authority (%s) failed", path)
		}
	}
	return pool, nil
}

// https://golang.org/src/crypto/tls/generate_cert.go as a function
func GenerateCert(ipaddr string) ([]byte, []byte, error) {
	var err error

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, keyBytes, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, keyBytes, err
	}

	notBefore := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"OAuth2 Proxy Test Suite"},
		},
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,

		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		IPAddresses: []net.IP{net.ParseIP(ipaddr)},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	return certBytes, keyBytes, err
}

// SplitHostPort separates host and port. If the port is not valid, it returns
// the entire input as host, and it doesn't check the validity of the host.
// Unlike net.SplitHostPort, but per RFC 3986, it requires ports to be numeric.
// *** taken from net/url, modified validOptionalPort() to accept ":*"
func SplitHostPort(hostport string) (host, port string) {
	host = hostport

	colon := strings.LastIndexByte(host, ':')
	if colon != -1 && validOptionalPort(host[colon:]) {
		host, port = host[:colon], host[colon+1:]
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}

	return
}

// validOptionalPort reports whether port is either an empty string
// or matches /^:\d*$/
// *** taken from net/url, modified to accept ":*"
func validOptionalPort(port string) bool {
	if port == "" || port == ":*" {
		return true
	}
	if port[0] != ':' {
		return false
	}
	for _, b := range port[1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

// IsEndpointAllowed checks whether the endpoint URL is allowed based
// on an allowed domains list.
func IsEndpointAllowed(endpoint *url.URL, allowedDomains []string) bool {
	hostname := endpoint.Hostname()

	for _, allowedDomain := range allowedDomains {
		allowedHost, allowedPort := SplitHostPort(allowedDomain)
		if allowedHost == "" {
			continue
		}

		if isHostnameAllowed(hostname, allowedHost) {
			// the domain names match, now validate the ports
			// if the allowed domain's port is '*', allow all ports
			// if the allowed domain contains a specific port, only allow that port
			// if the allowed domain doesn't contain a port at all, only allow empty redirect ports ie http and https
			redirectPort := endpoint.Port()
			if allowedPort == "*" ||
				allowedPort == redirectPort ||
				(allowedPort == "" && redirectPort == "") {
				return true
			}
		}
	}

	return false
}

func isHostnameAllowed(hostname, allowedHost string) bool {
	// check if we have a perfect match between hostname and allowedHost
	if hostname == strings.TrimPrefix(allowedHost, ".") ||
		hostname == strings.TrimPrefix(allowedHost, "*.") {
		return true
	}

	// check if hostname is a sub domain of the allowedHost
	if (strings.HasPrefix(allowedHost, ".") && strings.HasSuffix(hostname, allowedHost)) ||
		(strings.HasPrefix(allowedHost, "*.") && strings.HasSuffix(hostname, allowedHost[1:])) {
		return true
	}

	return false
}

// RemoveDuplicateStr removes duplicates from a slice of strings.
func RemoveDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]struct{})
	var list []string
	for _, item := range strSlice {
		if _, ok := allKeys[item]; !ok {
			allKeys[item] = struct{}{}
			list = append(list, item)
		}
	}
	return list
}

const (
	// ServiceAccountCAPath is the path to the Kubernetes service account CA certificate
	ServiceAccountCAPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	// ServiceAccountTokenPath is the path to the Kubernetes service account token
	ServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" // #nosec G101
	// ServiceAccountNamespacePath is the path to the Kubernetes service account namespace
	ServiceAccountNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	// kubernetesDefaultService is the default Kubernetes service DNS name
	kubernetesDefaultService = "kubernetes.default.svc"
)

// GetKubernetesAPIHost returns the Kubernetes API server host from environment
// variables (KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT) or falls back
// to the default service DNS name (kubernetes.default.svc).
func GetKubernetesAPIHost() string {
	host := kubernetesDefaultService

	if h := os.Getenv("KUBERNETES_SERVICE_HOST"); h != "" {
		// Handle IPv6 addresses
		if strings.Contains(h, ":") {
			h = "[" + h + "]"
		}
		host = h
	}

	if port := os.Getenv("KUBERNETES_SERVICE_PORT"); port != "" {
		host = host + ":" + port
	}

	return host
}

// GetKubernetesAPIURL constructs a URL for the Kubernetes API with the given path.
func GetKubernetesAPIURL(path string) string {
	return "https://" + GetKubernetesAPIHost() + path
}

// NewKubernetesHTTPClient creates an HTTP client configured with the appropriate
// CA certificates for connecting to the Kubernetes API server.
// If caFiles is empty, it defaults to the service account CA.
// If useSystemTrustStore is true, system root CAs are also included.
// If insecureSkipVerify is true, TLS certificate verification is disabled.
func NewKubernetesHTTPClient(caFiles []string, useSystemTrustStore, insecureSkipVerify bool) (*http.Client, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// #nosec G402 -- InsecureSkipVerify is a configurable option
		InsecureSkipVerify: insecureSkipVerify,
	}

	if !insecureSkipVerify {
		capaths := caFiles
		if len(capaths) == 0 {
			capaths = []string{ServiceAccountCAPath}
		}

		var pool *x509.CertPool
		if useSystemTrustStore {
			if systemPool, err := x509.SystemCertPool(); err == nil {
				pool = systemPool
			} else {
				pool = x509.NewCertPool()
			}
		} else {
			pool = x509.NewCertPool()
		}

		for _, caPath := range capaths {
			caPEM, err := os.ReadFile(caPath) // #nosec G304 - CA paths are configurable
			if err != nil {
				return nil, fmt.Errorf("failed to read CA file %s: %v", caPath, err)
			}
			if !pool.AppendCertsFromPEM(caPEM) {
				return nil, fmt.Errorf("failed to parse CA certificate from %s", caPath)
			}
		}

		tlsConfig.RootCAs = pool
	}

	return &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: tlsConfig,
		},
		Timeout: 1 * time.Minute,
	}, nil
}
