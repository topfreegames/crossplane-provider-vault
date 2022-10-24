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
	"testing"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/crossplane/crossplane-runtime/pkg/test"
	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"github.com/topfreegames/crossplane-provider-vault/apis/auth/v1alpha1"
	"github.com/topfreegames/crossplane-provider-vault/internal/clients"
	"github.com/topfreegames/crossplane-provider-vault/internal/clients/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
)

// Unlike many Kubernetes projects Crossplane does not use third party testing
// libraries, per the common Go test review comments. Crossplane encourages the
// use of table driven unit tests. The tests of the crossplane-runtime project
// are representative of the testing style Crossplane encourages.
//
// https://github.com/golang/go/wiki/TestComments
// https://github.com/crossplane/crossplane/blob/master/CONTRIBUTING.md#contributing-code

func TestObserve(t *testing.T) {
	type fields struct {
		clientBuilder func(t *testing.T) clients.VaultClient
	}

	type args struct {
		ctx context.Context
		mg  resource.Managed
	}

	type want struct {
		o   managed.ExternalObservation
		err error
	}

	cases := map[string]struct {
		reason string
		fields fields
		args   args
		want   want
	}{
		"does not exist": {
			reason: "JWT/OIDC role should not exist",
			fields: fields{
				clientBuilder: func(t *testing.T) clients.VaultClient {
					jwtRole := getTestRole()

					name := jwtRole.Name
					path := jwtAuthBackendRolePath(*jwtRole.Spec.ForProvider.Backend, name)

					clientMock, logicalMock := newMock(t)
					logicalMock.EXPECT().Read(path).Return(&api.Secret{}, errors.New("role does not exist"))

					return clientMock
				},
			},
			args: args{
				ctx: context.TODO(),
				mg:  getTestRole(),
			},
			want: want{
				o: managed.ExternalObservation{
					ResourceExists:          false,
					ResourceUpToDate:        true,
					ResourceLateInitialized: false,
					ConnectionDetails:       managed.ConnectionDetails{},
				},
				err: nil,
			},
		},
		"exists but outdated": {
			reason: "role exists but is outdated",
			fields: fields{
				clientBuilder: func(t *testing.T) clients.VaultClient {
					role := getTestRole()

					path := jwtAuthBackendRolePath(*role.Spec.ForProvider.Backend, role.Name)
					secret := &api.Secret{
						RequestID:     "",
						LeaseID:       "",
						LeaseDuration: 0,
						Renewable:     false,
						Data: map[string]interface{}{
							"role_type": "oidc",
						},
						Warnings: []string{},
						Auth:     &api.SecretAuth{},
						WrapInfo: &api.SecretWrapInfo{},
					}

					clientMock, logicalMock := newMock(t)
					logicalMock.EXPECT().Read(path).Return(secret, nil)

					return clientMock
				},
			},
			args: args{
				ctx: context.TODO(),
				mg:  getTestRole(),
			},
			want: want{
				o: managed.ExternalObservation{
					ResourceExists:          true,
					ResourceUpToDate:        false,
					ResourceLateInitialized: false,
					ConnectionDetails:       managed.ConnectionDetails{},
				},
				err: nil,
			},
		},
		"exists and is up to date": {
			reason: "role exists but is outdated",
			fields: fields{
				clientBuilder: func(t *testing.T) clients.VaultClient {
					role := getTestRole()

					path := jwtAuthBackendRolePath(*role.Spec.ForProvider.Backend, role.Name)
					secret := &api.Secret{
						RequestID:     "",
						LeaseID:       "",
						LeaseDuration: 0,
						Renewable:     false,
						Data: map[string]interface{}{
							"role_type": "jwt",
							"backend":   "gitlab",
						},
						Warnings: []string{},
						Auth:     &api.SecretAuth{},
						WrapInfo: &api.SecretWrapInfo{},
					}

					clientMock, logicalMock := newMock(t)
					logicalMock.EXPECT().Read(path).Return(secret, nil)

					return clientMock
				},
			},
			args: args{
				ctx: context.TODO(),
				mg:  getTestRole(),
			},
			want: want{
				o: managed.ExternalObservation{
					ResourceExists:          true,
					ResourceUpToDate:        false,
					ResourceLateInitialized: false,
					ConnectionDetails:       managed.ConnectionDetails{},
				},
				err: nil,
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := external{client: tc.fields.clientBuilder(t)}
			got, err := e.Observe(tc.args.ctx, tc.args.mg)
			if diff := cmp.Diff(tc.want.err, err, test.EquateErrors()); diff != "" {
				t.Errorf("\n%s\ne.Observe(...): -want error, +got error:\n%s\n", tc.reason, diff)
			}
			if diff := cmp.Diff(tc.want.o, got); diff != "" {
				t.Errorf("\n%s\ne.Observe(...): -want, +got:\n%s\n", tc.reason, diff)
			}
		})
	}
}

func TestCreate(t *testing.T) {
	type fields struct {
		clientBuilder func(t *testing.T) clients.VaultClient
	}

	type args struct {
		ctx context.Context
		mg  resource.Managed
	}

	type want struct {
		o   managed.ExternalCreation
		err error
	}

	cases := map[string]struct {
		reason string
		fields fields
		args   args
		want   want
	}{
		"successfully create": {
			reason: "Creates JWT/OIDC role",
			fields: fields{
				clientBuilder: func(t *testing.T) clients.VaultClient {
					jwtRole := getTestRole()

					name := jwtRole.Name
					path := jwtAuthBackendRolePath(*jwtRole.Spec.ForProvider.Backend, name)

					data := getVaultDefaultData()
					data["role_type"] = "jwt"
					data["role_name"] = "roleTest"
					secret := &api.Secret{
						RequestID:     "",
						LeaseID:       "",
						LeaseDuration: 0,
						Renewable:     false,
						Data:          data,
						Warnings:      []string{},
						Auth:          &api.SecretAuth{},
						WrapInfo:      &api.SecretWrapInfo{},
					}

					clientMock, logicalMock := newMock(t)
					logicalMock.EXPECT().Write(path, data).Return(secret, nil)

					return clientMock
				},
			},
			args: args{
				ctx: context.TODO(),
				mg:  getTestRole(),
			},
			want: want{
				o: managed.ExternalCreation{
					ExternalNameAssigned: false,
					ConnectionDetails:    managed.ConnectionDetails{},
				},
				err: nil,
			},
		},
		"fail creating role": {
			reason: "Fail creating JWT/OIDC role",
			fields: fields{
				clientBuilder: func(t *testing.T) clients.VaultClient {
					jwtRole := getTestRole()

					name := jwtRole.Name
					path := jwtAuthBackendRolePath(*jwtRole.Spec.ForProvider.Backend, name)

					data := getVaultDefaultData()
					data["role_type"] = "jwt"
					data["role_name"] = "roleTest"

					clientMock, logicalMock := newMock(t)
					logicalMock.EXPECT().Write(path, data).Return(nil, vaultMockError())

					return clientMock
				},
			},
			args: args{
				ctx: context.TODO(),
				mg:  getTestRole(),
			},
			want: want{
				o: managed.ExternalCreation{
					ExternalNameAssigned: false,
					ConnectionDetails:    nil,
				},
				err: errors.Wrap(vaultMockError(), errCreation),
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := external{client: tc.fields.clientBuilder(t)}
			got, err := e.Create(tc.args.ctx, tc.args.mg)
			if diff := cmp.Diff(tc.want.err, err, test.EquateErrors()); diff != "" {
				t.Errorf("\n%s\ne.Create(...): -want error, +got error:\n%s\n", tc.reason, diff)
			}
			if diff := cmp.Diff(tc.want.o, got); diff != "" {
				t.Errorf("\n%s\ne.Create(...): -want, +got:\n%s\n", tc.reason, diff)
			}
		})
	}
}

func TestUpdate(t *testing.T) {
	type fields struct {
		clientBuilder func(t *testing.T) clients.VaultClient
	}

	type args struct {
		ctx context.Context
		mg  resource.Managed
	}

	type want struct {
		o   managed.ExternalUpdate
		err error
	}

	cases := map[string]struct {
		reason string
		fields fields
		args   args
		want   want
	}{
		"successfully update": {
			reason: "Updates a JWT/OIDC role",
			fields: fields{
				clientBuilder: func(t *testing.T) clients.VaultClient {
					jwtRole := getTestRole()

					name := jwtRole.Name
					path := jwtAuthBackendRolePath(*jwtRole.Spec.ForProvider.Backend, name)

					data := getVaultDefaultData()
					data["role_type"] = "jwt"
					data["role_name"] = "roleTest"
					secret := &api.Secret{
						RequestID:     "",
						LeaseID:       "",
						LeaseDuration: 0,
						Renewable:     false,
						Data:          data,
						Warnings:      []string{},
						Auth:          &api.SecretAuth{},
						WrapInfo:      &api.SecretWrapInfo{},
					}

					clientMock, logicalMock := newMock(t)
					logicalMock.EXPECT().Write(path, data).Return(secret, nil)

					return clientMock
				},
			},
			args: args{
				ctx: context.TODO(),
				mg:  getTestRole(),
			},
			want: want{
				o: managed.ExternalUpdate{
					ConnectionDetails: managed.ConnectionDetails{},
				},
				err: nil,
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := external{client: tc.fields.clientBuilder(t)}
			got, err := e.Update(tc.args.ctx, tc.args.mg)
			if diff := cmp.Diff(tc.want.err, err, test.EquateErrors()); diff != "" {
				t.Errorf("\n%s\ne.Update(...): -want error, +got error:\n%s\n", tc.reason, diff)
			}
			if diff := cmp.Diff(tc.want.o, got); diff != "" {
				t.Errorf("\n%s\ne.Update(...): -want, +got:\n%s\n", tc.reason, diff)
			}
		})
	}
}

func TestDelete(t *testing.T) {
	type fields struct {
		clientBuilder func(t *testing.T) clients.VaultClient
	}

	type args struct {
		ctx context.Context
		mg  resource.Managed
	}

	type want struct {
		err error
	}

	cases := map[string]struct {
		reason string
		fields fields
		args   args
		want   want
	}{
		"successfully delete": {
			reason: "Delete an existing JWT/OIDC role",
			fields: fields{
				clientBuilder: func(t *testing.T) clients.VaultClient {
					jwtRole := getTestRole()

					name := jwtRole.Name
					path := jwtAuthBackendRolePath(*jwtRole.Spec.ForProvider.Backend, name)

					clientMock, logicalMock := newMock(t)
					logicalMock.EXPECT().Delete(path).Return(nil, nil)

					return clientMock
				},
			},
			args: args{
				ctx: context.TODO(),
				mg:  getTestRole(),
			},
			want: want{
				err: nil,
			},
		},
		"fail to delete": {
			reason: "Fail to delete a JWT/OIDC role",
			fields: fields{
				clientBuilder: func(t *testing.T) clients.VaultClient {
					jwtRole := getTestRole()

					name := jwtRole.Name
					path := jwtAuthBackendRolePath(*jwtRole.Spec.ForProvider.Backend, name)

					clientMock, logicalMock := newMock(t)
					logicalMock.EXPECT().Delete(path).Return(nil, vaultMockError())

					return clientMock
				},
			},
			args: args{
				ctx: context.TODO(),
				mg:  getTestRole(),
			},
			want: want{
				err: errors.Wrap(vaultMockError(), errDelete),
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := external{client: tc.fields.clientBuilder(t)}
			err := e.Delete(tc.args.ctx, tc.args.mg)
			if diff := cmp.Diff(tc.want.err, err, test.EquateErrors()); diff != "" {
				t.Errorf("\n%s\ne.Delete(...): -want error, +got error:\n%s\n", tc.reason, diff)
			}
		})
	}
}

func getTestRole() *v1alpha1.Jwt {
	return &v1alpha1.Jwt{
		TypeMeta: metav1.TypeMeta{
			Kind:       v1alpha1.JwtKind,
			APIVersion: v1alpha1.JwtKindAPIVersion,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "roleTest",
		},
		Spec: v1alpha1.JwtSpec{
			ResourceSpec: xpv1.ResourceSpec{
				DeletionPolicy: "Delete",
			},
			ForProvider: v1alpha1.JwtParameters{
				Backend:  pointer.String("gitlab"),
				RoleType: pointer.String("jwt"),
			},
		},
	}
}

func newMock(t *testing.T) (*fake.MockVaultClient, *fake.MockVaultLogicalClient) {
	ctrl := gomock.NewController(t)
	logicalMock := fake.NewMockVaultLogicalClient(ctrl)

	clientMock := fake.NewMockVaultClient(ctrl)
	clientMock.EXPECT().Logical().Return(logicalMock)

	return clientMock, logicalMock
}

func vaultMockError() error {
	return errors.New("fake error message")
}

func getVaultDefaultData() map[string]interface{} {
	return map[string]interface{}{
		"role_name":               "",
		"namespace":               "",
		"role_type":               "",
		"bound_audiences":         []interface{}{},
		"user_claim":              "",
		"user_claim_json_pointer": false,
		"bound_subject":           "",
		"bound_claims":            map[string]interface{}{},
		"bound_claims_type":       "",
		"claim_mappings":          map[string]interface{}{},
		"oidc_scopes":             []interface{}{},
		"groups_claim":            "",
		"allowed_redirect_uris":   []interface{}{},
		"clock_skew_leeway":       float64(0),
		"expiration_leeway":       float64(0),
		"not_before_leeway":       float64(0),
		"verbose_oidc_logging":    false,
		"max_age":                 float64(0),
		"token_ttl":               float64(0),
		"token_max_ttl":           float64(0),
		"token_policies":          []interface{}{},
		"token_bound_cidrs":       []interface{}{},
		"token_explicit_max_ttl":  float64(0),
		"token_no_default_policy": false,
		"token_num_uses":          float64(0),
		"token_period":            float64(0),
		"token_type":              "",
	}
}
