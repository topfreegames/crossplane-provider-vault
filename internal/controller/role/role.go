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

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/davecgh/go-spew/spew"
	"github.com/hashicorp/vault/api"
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
	errCreation          = "cannot create secret backend role"
	errUpdate            = "cannot update secret backend role"
	errDelete            = "cannot delete secret backend role"
	errRead              = "cannot read secret backend role"

	// Validation Errors
	errValidationMessage  = "validation error for AWS Secret Backend Role"
	errUnkownCredType     = "credential_type must be one of iam_user, assumed_role, or federation_token"
	errMinRequirements    = "at least one of: `policy_document`, `policy_arns`, `role_arns` or `iam_groups` must be set"
	errPermissionBoundary = "permissions_boundary_arn is only valid when credential_type is iam_user"
	errUserPath           = "user_path is only valid when credential_type is iam_user"
	errMaxTTL             = "max_sts_ttl is only valid when credential_type is assumed_role or federation_token"
	errDefaultSts         = "default_sts_ttl is only valid when credential_type is assumed_role or federation_token"
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
	role, ok := mg.(*v1alpha1.Role)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotRole)
	}

	name := role.Name
	authBackend := role.Spec.ForProvider.Backend

	path := authBackend + "/roles/" + name

	// c.logger.Debug("Reading role from %q", path)

	print(path)
	secret, err := c.client.Logical().Read(path)
	if err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, errRead)
	}
	// c.logger.Debug("Read role from %q", path)

	exists := err == nil && secret != nil

	spew.Dump(secret)
	spew.Dump(role)

	upToDate := false
	if exists {
		upToDate = role.Spec.ForProvider.Backend == secret.Data["backend"]
	}

	if exists && upToDate {
		role.SetConditions(xpv1.Available())
	}

	return managed.ExternalObservation{
		// Return false when the external resource does not exist. This lets
		// the managed resource reconciler know that it needs to call Create to
		// (re)create the resource, or that it has successfully been deleted.
		ResourceExists: exists,

		// Return false when the external resource exists, but it not up to date
		// with the desired managed resource state. This lets the managed
		// resource reconciler know that it needs to call Update.
		ResourceUpToDate: upToDate,

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

	_, err := c.writeRole(role)
	if err != nil {
		return managed.ExternalCreation{
			ExternalNameAssigned: false,
			ConnectionDetails:    nil,
		}, errors.Wrap(err, errCreation)
	}

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

	_, err := c.writeRole(role)
	if err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, errUpdate)
	}

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
	authBackend := role.Spec.ForProvider.Backend

	c.logger.Debug("Deleting role %q on AWS backend %q", name, authBackend)
	_, err := c.client.Logical().Delete(authBackend + "/roles/" + name)
	if err != nil {
		return errors.Wrap(err, errDelete)
	}
	c.logger.Debug("Deleted role %q on AWS backend %q", name, authBackend)

	return nil
}

// validate the role as some fields are only allowed in case another field has a different value
func validate(role *v1alpha1.Role) error {

	credentialType := role.Spec.ForProvider.CredentialType
	iamRolesArn := role.Spec.ForProvider.IamRolesArn
	policiesArn := role.Spec.ForProvider.PoliciesArn
	policyDocument := role.Spec.ForProvider.PolicyDocument
	iamGroups := role.Spec.ForProvider.IamGroups
	userPath := role.Spec.ForProvider.UserPath
	permissionsBoundaryArn := role.Spec.ForProvider.PermissionBoundaryArn
	defaultStsTTL := role.Spec.ForProvider.DefaultStsTTL
	maxStsTTL := role.Spec.ForProvider.MaxStsTTL

	if credentialType != "iam_user" && credentialType != "assumed_role" && credentialType != "federation_token" {
		return errors.New(errUnkownCredType)
	}

	if policyDocument == "" && len(policiesArn) == 0 && len(iamRolesArn) == 0 && len(iamGroups) == 0 {
		return errors.New(errMinRequirements)
	}

	if credentialType != "iam_user" {
		if permissionsBoundaryArn != "" {
			return errors.New(errPermissionBoundary)
		}
		if userPath != "" {
			return errors.New(errUserPath)
		}
	}

	if credentialType != "assumed_role" && credentialType != "federation_token" {
		if maxStsTTL > 0 {
			return errors.New(errMaxTTL)
		}
		if defaultStsTTL > 0 {
			return errors.New(errDefaultSts)
		}
	}

	return nil
}

// write role validate the role and create it
func (c *external) writeRole(role *v1alpha1.Role) (*api.Secret, error) {
	validErr := validate(role)
	if validErr != nil {
		return nil, validErr
		// errors.Wrap(validErr, errValidationMessage)
	}

	data, err := crossplaneToVaultFunc(role)
	if err != nil {
		return nil, fmt.Errorf("error decoding role spec: %w", err)
	}

	name := role.Name
	backend := role.Spec.ForProvider.Backend
	path := backend + "/roles/" + name

	c.logger.Debug("Creating/Updating role %q on AWS backend %q", name, backend)
	secret, err := c.client.Logical().Write(path, data)
	if err != nil {
		c.logger.Debug(fmt.Sprintf("error creating role %q for backend %q: %s", name, backend, err))
		return nil, errors.Wrap(err, errCreation)
	}
	c.logger.Debug("Created/Updated role %q on AWS backend %q", name, backend)

	return secret, nil
}
