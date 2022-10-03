package clients

import (
	"context"

	"github.com/crossplane/crossplane-runtime/pkg/resource"
	apisv1alpha1 "github.com/crossplane/provider-vault/apis/v1alpha1"
	vault "github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	errTrackPCUsage      = "cannot track ProviderConfig usage"
	errGetPC             = "cannot get ProviderConfig"
	errGetCreds          = "cannot get credentials"
	errNewExternalClient = "cannot create vault client from config"
)

// NewVaultClient creates a new Vault client.
// This function should be used in the Connect method of controller connectors.
func NewVaultClient(ctx context.Context, kube client.Client, mg resource.Managed) (*vault.Client, error) {

	tracker := resource.NewProviderConfigUsageTracker(kube, &apisv1alpha1.ProviderConfigUsage{})
	if err := tracker.Track(ctx, mg); err != nil {
		return nil, errors.Wrap(err, errTrackPCUsage)
	}

	pc := &apisv1alpha1.ProviderConfig{}
	if err := kube.Get(ctx, types.NamespacedName{Name: mg.GetProviderConfigReference().Name}, pc); err != nil {
		return nil, errors.Wrap(err, errGetPC)
	}

	cd := pc.Spec.Credentials
	token, err := resource.CommonCredentialExtractor(ctx, cd.Source, kube, cd.CommonCredentialSelectors)
	if err != nil {
		return nil, errors.Wrap(err, errGetCreds)
	}

	vaultClient, err := vault.NewClient(&vault.Config{
		Address: pc.Spec.Address,
		Timeout: pc.Spec.Timeout,
	})
	if err != nil {
		return nil, errors.Wrap(err, errNewExternalClient)
	}

	vaultClient.SetToken(string(token))

	return vaultClient, nil
}
