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

package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/logging"
	"github.com/crossplane/crossplane-runtime/pkg/ratelimiter"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"

	"github.com/topfreegames/crossplane-provider-vault/apis/auth/v1alpha1"
	apisv1alpha1 "github.com/topfreegames/crossplane-provider-vault/apis/v1alpha1"
	"github.com/topfreegames/crossplane-provider-vault/internal/clients"
	"github.com/topfreegames/crossplane-provider-vault/internal/controller/features"
)

const (
	errNotJwt       = "managed resource is not a Jwt custom resource"
	errTrackPCUsage = "cannot track ProviderConfig usage"
	errGetPC        = "cannot get ProviderConfig"
	errGetCreds     = "cannot get credentials"

	errNewClient         = "cannot create new Service"
	errNewExternalClient = "cannot create vault client from config"

	errCreation = "cannot create JWT role"
	errUpdate   = "cannot update JWT role"
	errDelete   = "cannot delete JWT role"
)

// A NoOpService does nothing.
type NoOpService struct{}

var (
	newNoOpService = func(_ []byte) (interface{}, error) { return &NoOpService{}, nil }
)

// Setup adds a controller that reconciles Jwt managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.JwtGroupKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), apisv1alpha1.StoreConfigGroupVersionKind))
	}

	r := managed.NewReconciler(mgr,
		resource.ManagedKind(v1alpha1.JwtGroupVersionKind),
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
		For(&v1alpha1.Jwt{}).
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
	cr, ok := mg.(*v1alpha1.Jwt)
	if !ok {
		return nil, errors.New(errNotJwt)
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
	role, ok := mg.(*v1alpha1.Jwt)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotJwt)
	}

	exists := false
	upToDate := true

	path := jwtAuthBackendRolePath(*role.Spec.ForProvider.Backend, role.Name)
	response, err := c.client.Logical().Read(path)
	if response != nil && err == nil {
		exists = true

		crossplaneData, err := decodeData(role)
		if err != nil {
			return managed.ExternalObservation{}, fmt.Errorf("error decoding data from role: %w", err)
		}
		upToDate = isUpToDate(c.logger, crossplaneData, response.Data)
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

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	role, ok := mg.(*v1alpha1.Jwt)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotJwt)
	}

	path := jwtAuthBackendRolePath(*role.Spec.ForProvider.Backend, role.Name)

	data, err := decodeData(role)
	if err != nil {
		return managed.ExternalCreation{}, fmt.Errorf("error decoding jwt role spec: %w", err)
	}

	_, err = c.client.Logical().Write(path, data)
	if err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, errCreation)
	}

	return managed.ExternalCreation{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	role, ok := mg.(*v1alpha1.Jwt)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotJwt)
	}

	data, err := decodeData(role)
	if err != nil {
		return managed.ExternalUpdate{}, fmt.Errorf("error decoding jwt role spec: %w", err)
	}
	path := jwtAuthBackendRolePath(*role.Spec.ForProvider.Backend, role.Name)
	_, err = c.client.Logical().Write(path, data)
	if err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, errUpdate)
	}

	return managed.ExternalUpdate{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	role, ok := mg.(*v1alpha1.Jwt)
	if !ok {
		return errors.New(errNotJwt)
	}

	path := jwtAuthBackendRolePath(*role.Spec.ForProvider.Backend, role.Name)
	_, err := c.client.Logical().Delete(path)
	if err != nil {
		return errors.Wrap(err, errDelete)
	}

	return nil
}

func decodeData(data *v1alpha1.Jwt) (map[string]interface{}, error) {
	d := map[string]interface{}{}
	jsonObj, _ := json.Marshal(data.Spec.ForProvider)
	json.Unmarshal(jsonObj, &d)
	d["role_name"] = data.ObjectMeta.Name
	return d, nil
}

func jwtAuthBackendRolePath(backend, role string) string {
	return "auth/" + strings.Trim(backend, "/") + "/role/" + strings.Trim(role, "/")
}

func isUpToDate(logger logging.Logger, crossplaneData, vaultData map[string]interface{}) bool {
	for key, value := range crossplaneData {
		if key == "backend" {
			continue
		}
		d, ok := vaultData[key]
		if !ok || fmt.Sprintf("%v", value) != fmt.Sprintf("%v", d) {
			return false
		}
	}
	return true
}
