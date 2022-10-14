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
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/crossplane/crossplane-runtime/pkg/test"
	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
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

func TestCreate(t *testing.T) {
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
		// TODO: continue the test from here
		"successfully create": {
			reason: "role must be created",
			fields: fields{
				clientBuilder: func(t *testing.T) clients.VaultClient {
					ctrl := gomock.NewController(t)
					clientMock := fake.NewMockVaultClient(ctrl)

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
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := &external{
				client: tc.fields.clientBuilder(t),
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
				CredentialType: "assume_role",
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
