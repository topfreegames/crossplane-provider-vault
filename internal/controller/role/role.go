/*
Copyright 2022 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
This functions were developed based on https://github.com/hashicorp/terraform-provider-vault/blob/main/vault/resource_aws_secret_backend_role.go
*/

package role

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/logging"
	"github.com/crossplane/crossplane-runtime/pkg/ratelimiter"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"

	"github.com/topfreegames/crossplane-provider-vault/apis/aws/v1alpha1"
	apisv1alpha1 "github.com/topfreegames/crossplane-provider-vault/apis/v1alpha1"
	"github.com/topfreegames/crossplane-provider-vault/internal/clients"
	"github.com/topfreegames/crossplane-provider-vault/internal/controller/features"
)

const (
	errNotRole      = "managed resource is not a Role custom resource"
	errTrackPCUsage = "cannot track ProviderConfig usage"
	errGetPC        = "cannot get ProviderConfig"
	errGetCreds     = "cannot get credentials"

	errNewClient         = "cannot create new Service"
	errNewExternalClient = "cannot create vault client from config"
)

// A NoOpService does nothing.
type NoOpService struct{}

var (
	newNoOpService = func(_ []byte) (interface{}, error) { return &NoOpService{}, nil }
)

// Setup adds a controller that reconciles Role managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.RoleGroupKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), apisv1alpha1.StoreConfigGroupVersionKind))
	}

	r := managed.NewReconciler(mgr,
		resource.ManagedKind(v1alpha1.RoleGroupVersionKind),
		managed.WithExternalConnecter(&connector{
			kube:         mgr.GetClient(),
			usage:        resource.NewProviderConfigUsageTracker(mgr.GetClient(), &apisv1alpha1.ProviderConfigUsage{}),
			newServiceFn: newNoOpService,
			logger:       o.Logger}),
		managed.WithLogger(o.Logger.WithValues("controller", name)),
		managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
		managed.WithConnectionPublishers(cps...))

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		For(&v1alpha1.Role{}).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

// A connector is expected to produce an ExternalClient when its Connect method
// is called.
type connector struct {
	kube         client.Client
	usage        resource.Tracker
	newServiceFn func(creds []byte) (interface{}, error)
	logger       logging.Logger
}

// Connect typically produces an ExternalClient by:
// 1. Tracking that the managed resource is using a ProviderConfig.
// 2. Getting the managed resource's ProviderConfig.
// 3. Getting the credentials specified by the ProviderConfig.
// 4. Using the credentials to form a client.
func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*v1alpha1.Role)
	if !ok {
		return nil, errors.New(errNotRole)
	}

	vaultClient, err := clients.NewVaultClient(ctx, c.kube, cr)
	if err != nil {
		return nil, errors.Wrap(err, errNewExternalClient)
	}

	return &external{
		client: vaultClient,
		logger: c.logger,
	}, nil
}

// An ExternalClient observes, then either creates, updates, or deletes an
// external resource to ensure it reflects the managed resource's desired state.
type external struct {
	// A 'client' used to connect to the external resource API. In practice this
	// would be something like an AWS SDK client.
	client clients.VaultClient

	logger logging.Logger
}

func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.Role)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotRole)
	}

	// These logger statements should be removed in the real implementation.
	c.logger.Info("Observing:", "cr", cr)

	return managed.ExternalObservation{
		// Return false when the external resource does not exist. This lets
		// the managed resource reconciler know that it needs to call Create to
		// (re)create the resource, or that it has successfully been deleted.
		ResourceExists: true,

		// Return false when the external resource exists, but it not up to date
		// with the desired managed resource state. This lets the managed
		// resource reconciler know that it needs to call Update.
		ResourceUpToDate: true,

		// Return any details that may be required to connect to the external
		// resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

// Create an AWS Secret Backend Role
func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	role, ok := mg.(*v1alpha1.Role)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotRole)
	}

	name := role.Name
	authBackend := role.Spec.ForProvider.AuthBackend
	credentialType := role.Spec.ForProvider.CredentialType
	iamRoles := role.Spec.ForProvider.IamRolesArn

	data := map[string]interface{}{}
	data["credential_type"] = credentialType
	data["role_arns"] = iamRoles
	data["default_sts_ttl"] = 3600

	c.logger.Debug("Creating role %q on AWS backend %q", name, authBackend)
	_, err := c.client.Logical().Write(authBackend+"/roles/"+name, data)
	if err != nil {
		return managed.ExternalCreation{}, fmt.Errorf("error creating role %q for backend %q: %s", name, authBackend, err)
	}
	c.logger.Debug("Created role %q on AWS backend %q", name, authBackend)

	return managed.ExternalCreation{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

// Update an AWS Secret Backend Role - Thats the same approach we use for create it.
func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	role, ok := mg.(*v1alpha1.Role)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotRole)
	}

	name := role.Name
	authBackend := role.Spec.ForProvider.AuthBackend
	credentialType := role.Spec.ForProvider.CredentialType
	iamRoles := role.Spec.ForProvider.IamRolesArn

	data := map[string]interface{}{}
	data["credential_type"] = credentialType
	data["role_arns"] = iamRoles
	data["default_sts_ttl"] = 3600

	c.logger.Debug("Updating (overwriting) role %q on AWS backend %q", name, authBackend)
	_, err := c.client.Logical().Write(authBackend+"/roles/"+name, data)
	if err != nil {
		return managed.ExternalUpdate{}, fmt.Errorf("error updating (overwriting) role %q for backend %q: %s", name, authBackend, err)
	}
	c.logger.Debug("Updated (overwritten) role %q on AWS backend %q", name, authBackend)

	return managed.ExternalUpdate{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

// Delete an AWS Secret Backend Role
func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	role, ok := mg.(*v1alpha1.Role)
	if !ok {
		return errors.New(errNotRole)
	}

	name := role.Name
	authBackend := role.Spec.ForProvider.AuthBackend

	c.logger.Debug("Deleting role %q on AWS backend %q", name, authBackend)
	_, err := c.client.Logical().Delete(authBackend + "/roles/" + name)
	if err != nil {
		return fmt.Errorf("error deleting role %q for backend %q: %s", name, authBackend, err)
	}
	c.logger.Debug("Deleted role %q on AWS backend %q", name, authBackend)

	return nil
}