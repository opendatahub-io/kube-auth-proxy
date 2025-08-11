package validation

import (
	"fmt"
	"os"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

// validateProviders is the initial validation migration for multiple providrers
// It currently includes only logic that can verify the providers one by one and does not break the valdation pipe
func validateProviders(o *options.Options) []string {
	msgs := []string{}

	// validate general multiple provider configuration
	if len(o.Providers) == 0 {
		msgs = append(msgs, "at least one provider has to be defined")
	}
	if o.SkipProviderButton && len(o.Providers) > 1 {
		msgs = append(msgs, "SkipProviderButton and multiple providers are mutually exclusive")
	}

	providerIDs := make(map[string]struct{})

	for _, provider := range o.Providers {
		msgs = append(msgs, validateProvider(provider, providerIDs)...)
	}

	return msgs
}

func validateProvider(provider options.Provider, providerIDs map[string]struct{}) []string {
	msgs := []string{}

	if provider.ID == "" {
		msgs = append(msgs, "provider has empty id: ids are required for all providers")
	}

	// Ensure provider IDs are unique
	if _, ok := providerIDs[provider.ID]; ok {
		msgs = append(msgs, fmt.Sprintf("multiple providers found with id %s: provider ids must be unique", provider.ID))
	}
	providerIDs[provider.ID] = struct{}{}

	if provider.ClientID == "" {
		msgs = append(msgs, "provider missing setting: client-id")
	}

	if providerRequiresClientSecret(provider) {
		msgs = append(msgs, validateClientSecret(provider)...)
	}

	return msgs
}

// providerRequiresClientSecret determines whether a provider must supply a client secret.
// Currently always returns true (confidential clients only).
func providerRequiresClientSecret(_ options.Provider) bool {
	return true
}

func validateClientSecret(provider options.Provider) []string {
	msgs := []string{}

	if provider.ClientSecret == "" && provider.ClientSecretFile == "" {
		msgs = append(msgs, "missing setting: client-secret or client-secret-file")
	}
	if provider.ClientSecret == "" && provider.ClientSecretFile != "" {
		_, err := os.ReadFile(provider.ClientSecretFile)
		if err != nil {
			msgs = append(msgs, "could not read client secret file: "+provider.ClientSecretFile)
		}
	}

	return msgs
}
