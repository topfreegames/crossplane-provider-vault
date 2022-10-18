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

package role

import (
	"context"
	"testing"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/logging"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/crossplane/crossplane-runtime/pkg/test"
	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"github.com/topfreegames/crossplane-provider-vault/apis/aws/v1alpha1"
	"github.com/topfreegames/crossplane-provider-vault/internal/clients"
	"github.com/topfreegames/crossplane-provider-vault/internal/clients/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Unlike many Kubernetes projects Crossplane does not use third party testing
// libraries, per the common Go test review comments. Crossplane encourages the
// use of table driven unit tests. The tests of the crossplane-runtime project
// are representative of the testing style Crossplane encourages.
//
// https://github.com/golang/go/wiki/TestComments
// https://github.com/crossplane/crossplane/blob/master/CONTRIBUTING.md#contributing-code

func getTestError() error {
	return errors.New("test error")
}

func getTestDontExistError() error {
	return errors.New("role does not exist")
}

func getTestUnknownCredTypeError() error {
	return errors.New(errUnkownCredType)
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
			reason: "role must be created",
			fields: fields{
				clientBuilder: func(t *testing.T) clients.VaultClient {

					role := getTestRole()
					data, _ := crossplaneToVaultFunc(role)

					name := role.Name
					backend := role.Spec.ForProvider.Backend
					path := backend + "/roles/" + name

					ctrl := gomock.NewController(t)
					logicalMock := fake.NewMockVaultLogicalClient(ctrl)

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

					logicalMock.EXPECT().Write(path, data).Return(secret, nil)

					clientMock := fake.NewMockVaultClient(ctrl)
					clientMock.EXPECT().Logical().Return(logicalMock)
					return clientMock
				},
			},
			args: args{
				ctx: context.TODO(),
				mg:  getTestRole(),
			},
			want: want{
				o: managed.ExternalCreation{
					ConnectionDetails: managed.ConnectionDetails{},
				},
				err: nil,
			},
		},
		"error validating role": {
			reason: "role is invalid",
			fields: fields{
				clientBuilder: func(t *testing.T) clients.VaultClient {

					invRole := getTestInvalidRole()
					invData, _ := crossplaneToVaultFunc(invRole)

					name := invRole.Name
					backend := invRole.Spec.ForProvider.Backend
					path := backend + "/roles/" + name

					ctrl2 := gomock.NewController(t)
					logicalMock := fake.NewMockVaultLogicalClient(ctrl2)

					logicalMock.EXPECT().Write(path, invData).Return(nil, nil)

					clientMock2 := fake.NewMockVaultClient(ctrl2)
					clientMock2.EXPECT().Logical().Return(logicalMock)
					return clientMock2
				},
			},
			args: args{
				ctx: context.TODO(),
				mg:  getTestInvalidRole(),
			},
			want: want{
				o: managed.ExternalCreation{
					ExternalNameAssigned: false,
					ConnectionDetails:    nil,
				},
				err: errors.Wrap(errors.New(errUnkownCredType), errCreation),
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := &external{
				client: tc.fields.clientBuilder(t),
				logger: logging.NewNopLogger(),
			}
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
		"doesn't exist": {
			reason: "role must not exist",
			fields: fields{
				clientBuilder: func(t *testing.T) clients.VaultClient {

					role := getTestRole()

					name := role.Name
					backend := role.Spec.ForProvider.Backend
					path := backend + "/roles/" + name

					ctrl := gomock.NewController(t)
					logicalMock := fake.NewMockVaultLogicalClient(ctrl)

					logicalMock.EXPECT().Read(path).Return(&api.Secret{}, getTestDontExistError())

					clientMock := fake.NewMockVaultClient(ctrl)
					clientMock.EXPECT().Logical().Return(logicalMock)
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
					ResourceUpToDate:        false,
					ResourceLateInitialized: false,
					ConnectionDetails:       map[string][]byte{},
				},
				err: nil,
			},
		},
		"exist but outdated": {
			reason: "role exists but its outdated",
			fields: fields{
				clientBuilder: func(t *testing.T) clients.VaultClient {

					role := getTestRole()

					name := role.Name
					backend := role.Spec.ForProvider.Backend
					path := backend + "/roles/" + name

					secret := &api.Secret{
						RequestID:     "",
						LeaseID:       "",
						LeaseDuration: 0,
						Renewable:     false,
						Data: map[string]interface{}{
							"test": "test",
						},
						Warnings: []string{},
						Auth:     &api.SecretAuth{},
						WrapInfo: &api.SecretWrapInfo{},
					}

					ctrl := gomock.NewController(t)
					logicalMock := fake.NewMockVaultLogicalClient(ctrl)

					logicalMock.EXPECT().Read(path).Return(secret, nil)

					clientMock := fake.NewMockVaultClient(ctrl)
					clientMock.EXPECT().Logical().Return(logicalMock)
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
					ConnectionDetails:       map[string][]byte{},
				},
				err: nil,
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := &external{
				client: tc.fields.clientBuilder(t),
			}
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

func getTestRole(f ...func(role *v1alpha1.Role) *v1alpha1.Role) *v1alpha1.Role {

	role := &v1alpha1.Role{
		TypeMeta: metav1.TypeMeta{
			Kind:       v1alpha1.RoleKind,
			APIVersion: v1alpha1.RoleKindAPIVersion,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "roletest",
		},
		Spec: v1alpha1.RoleSpec{
			ResourceSpec: xpv1.ResourceSpec{
				DeletionPolicy: "Delete",
			},
			ForProvider: v1alpha1.RoleParameters{
				Backend:        "aws",
				CredentialType: "assumed_role",
				IamRolesArn:    []string{"arn:aws:iam::123456789012:role/roletest"},
				// PoliciesArn:           []string{}, // We are using PolicyDocument
				PolicyDocument: `{
					"Version": "2012-10-17",
					"Statement": [
						{
							"Sid": "FirstStatement",
							"Effect": "Allow",
							"Action": ["iam:ChangePassword"],
							"Resource": "*"
						}
					]
				}`,
				IamGroups:             []string{},
				UserPath:              "",
				PermissionBoundaryArn: "",
				DefaultStsTTL:         3600,
				MaxStsTTL:             0,
			},
		},
		Status: v1alpha1.RoleStatus{},
	}

	for _, fun := range f {
		role = fun(role)
	}

	return role
}

func getTestInvalidRole(f ...func(role *v1alpha1.Role) *v1alpha1.Role) *v1alpha1.Role {

	role := &v1alpha1.Role{
		TypeMeta: metav1.TypeMeta{
			Kind:       v1alpha1.RoleKind,
			APIVersion: v1alpha1.RoleKindAPIVersion,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "invroletest",
		},
		Spec: v1alpha1.RoleSpec{
			ResourceSpec: xpv1.ResourceSpec{
				DeletionPolicy: "Delete",
			},
			ForProvider: v1alpha1.RoleParameters{
				Backend:        "aws",
				CredentialType: "invalid", // Error
				IamRolesArn:    []string{"arn:aws:iam::123456789012:role/roletest"},
				// PoliciesArn:           []string{}, // We are using PolicyDocument
				PolicyDocument: `{
					"Version": "2012-10-17",
					"Statement": [
						{
							"Sid": "FirstStatement",
							"Effect": "Allow",
							"Action": ["iam:ChangePassword"],
							"Resource": "*"
						}
					]
				}`,
				IamGroups:             []string{},
				UserPath:              "",
				PermissionBoundaryArn: "",
				DefaultStsTTL:         3600,
				MaxStsTTL:             0,
			},
		},
		Status: v1alpha1.RoleStatus{},
	}

	for _, fun := range f {
		role = fun(role)
	}

	return role
}
