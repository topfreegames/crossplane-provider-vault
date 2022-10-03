/*
Copyright 2020 The Crossplane Authors.

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

package policy

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	vault "github.com/hashicorp/vault/api"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/crossplane/crossplane-runtime/pkg/test"
	"github.com/crossplane/provider-vault/apis/sys/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
		service interface{}
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
			reason: "it doesn't exist",
			fields: fields{
				service: nil,
			},
			args: args{
				ctx: context.TODO(),
				mg: &v1alpha1.Policy{
					TypeMeta: metav1.TypeMeta{
						Kind:       v1alpha1.PolicyKind,
						APIVersion: v1alpha1.PolicyKindAPIVersion,
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "test",
					},
					Spec: v1alpha1.PolicySpec{
						ResourceSpec: xpv1.ResourceSpec{
							DeletionPolicy: "Delete",
						},
						ForProvider: v1alpha1.PolicyParameters{
							Rules: "path \"auth/*\" {\n  capabilities = [\"list\"]}",
						},
					},
				},
			},
			want: want{
				o: managed.ExternalObservation{
					ResourceExists:          false,
					ResourceUpToDate:        false,
					ResourceLateInitialized: false,
					ConnectionDetails:       map[string][]byte{},
					Diff:                    "",
				},
				err: nil,
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			vaultClient, _ := vault.NewClient(&vault.Config{
				Address: "http://127.0.0.1:8200",
			})

			vaultClient.SetToken("hvs.723oyiA9LFYHehGerJsoXaKn")
			e := &external{
				service: nil,
				client:  vaultClient,
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
