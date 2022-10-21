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
