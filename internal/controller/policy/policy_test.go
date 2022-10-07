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

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/crossplane/crossplane-runtime/pkg/test"
	"github.com/topfreegames/crossplane-provider-vault/apis/sys/v1alpha1"
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

func getTestPolicy(f ...func(pol *v1alpha1.Policy) *v1alpha1.Policy) *v1alpha1.Policy {
	pol := &v1alpha1.Policy{
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
	}
	for _, fun := range f {
		pol = fun(pol)
	}

	return pol
}

func getTestError() error {
	return errors.New("test error")
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
			reason: "policy should not exist",
			fields: fields{
				clientBuilder: func(t *testing.T) clients.VaultClient {
					ctrl := gomock.NewController(t)
					sysMock := fake.NewMockVaultSysClient(ctrl)
					sysMock.EXPECT().GetPolicy(getTestPolicy().ObjectMeta.Name).Return("", nil)

					client := fake.NewMockVaultClient(ctrl)
					client.EXPECT().Sys().Return(sysMock)
					return client
				},
			},
			args: args{
				ctx: context.TODO(),
				mg:  getTestPolicy(),
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
			reason: "policy exist and be outdated",
			fields: fields{
				clientBuilder: func(t *testing.T) clients.VaultClient {
					ctrl := gomock.NewController(t)
					sysMock := fake.NewMockVaultSysClient(ctrl)
					sysMock.EXPECT().GetPolicy(getTestPolicy().ObjectMeta.Name).Return("some other value", nil)

					client := fake.NewMockVaultClient(ctrl)
					client.EXPECT().Sys().Return(sysMock)
					return client
				},
			},
			args: args{
				ctx: context.TODO(),
				mg:  getTestPolicy(),
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
		"client error": {
			reason: "resource doesn't exist in case of client error",
			fields: fields{
				clientBuilder: func(t *testing.T) clients.VaultClient {
					ctrl := gomock.NewController(t)
					sysMock := fake.NewMockVaultSysClient(ctrl)
					sysMock.EXPECT().GetPolicy(getTestPolicy().ObjectMeta.Name).Return("", getTestError())

					client := fake.NewMockVaultClient(ctrl)
					client.EXPECT().Sys().Return(sysMock)
					return client
				},
			},
			args: args{
				ctx: context.TODO(),
				mg:  getTestPolicy(),
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
			reason: "policy should be created successfully",
			fields: fields{
				clientBuilder: func(t *testing.T) clients.VaultClient {
					ctrl := gomock.NewController(t)
					sysMock := fake.NewMockVaultSysClient(ctrl)
					sysMock.EXPECT().PutPolicy(getTestPolicy().ObjectMeta.Name, getTestPolicy().Spec.ForProvider.Rules).Return(nil)

					client := fake.NewMockVaultClient(ctrl)
					client.EXPECT().Sys().Return(sysMock)
					return client
				},
			},
			args: args{
				ctx: context.TODO(),
				mg:  getTestPolicy(),
			},
			want: want{
				o: managed.ExternalCreation{
					ConnectionDetails: map[string][]byte{},
				},
				err: nil,
			},
		},
		"error creation": {
			reason: "error should be wrapped and bubbled up",
			fields: fields{
				clientBuilder: func(t *testing.T) clients.VaultClient {
					ctrl := gomock.NewController(t)
					sysMock := fake.NewMockVaultSysClient(ctrl)
					sysMock.EXPECT().PutPolicy("test", getTestPolicy().Spec.ForProvider.Rules).Return(getTestError())

					client := fake.NewMockVaultClient(ctrl)
					client.EXPECT().Sys().Return(sysMock)
					return client
				},
			},
			args: args{
				ctx: context.TODO(),
				mg:  getTestPolicy(),
			},
			want: want{
				o:   managed.ExternalCreation{},
				err: errors.Wrap(getTestError(), errCreation),
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
				t.Errorf("\n%s\ne.Observe(...): -want error, +got error:\n%s\n", tc.reason, diff)
			}
			if diff := cmp.Diff(tc.want.o, got); diff != "" {
				t.Errorf("\n%s\ne.Observe(...): -want, +got:\n%s\n", tc.reason, diff)
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
			reason: "policy should be updated successfully",
			fields: fields{
				clientBuilder: func(t *testing.T) clients.VaultClient {
					ctrl := gomock.NewController(t)
					sysMock := fake.NewMockVaultSysClient(ctrl)
					sysMock.EXPECT().PutPolicy(getTestPolicy().ObjectMeta.Name, getTestPolicy().Spec.ForProvider.Rules).Return(nil)

					client := fake.NewMockVaultClient(ctrl)
					client.EXPECT().Sys().Return(sysMock)
					return client
				},
			},
			args: args{
				ctx: context.TODO(),
				mg:  getTestPolicy(),
			},
			want: want{
				o: managed.ExternalUpdate{
					ConnectionDetails: map[string][]byte{},
				},
				err: nil,
			},
		},
		"error creation": {
			reason: "error should be wrapped and bubbled up",
			fields: fields{
				clientBuilder: func(t *testing.T) clients.VaultClient {
					ctrl := gomock.NewController(t)
					sysMock := fake.NewMockVaultSysClient(ctrl)
					sysMock.EXPECT().PutPolicy(getTestPolicy().ObjectMeta.Name, getTestPolicy().Spec.ForProvider.Rules).Return(getTestError())

					client := fake.NewMockVaultClient(ctrl)
					client.EXPECT().Sys().Return(sysMock)
					return client
				},
			},
			args: args{
				ctx: context.TODO(),
				mg:  getTestPolicy(),
			},
			want: want{
				o:   managed.ExternalUpdate{},
				err: errors.Wrap(getTestError(), errUpdate),
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := &external{
				client: tc.fields.clientBuilder(t),
			}
			got, err := e.Update(tc.args.ctx, tc.args.mg)
			if diff := cmp.Diff(tc.want.err, err, test.EquateErrors()); diff != "" {
				t.Errorf("\n%s\ne.Observe(...): -want error, +got error:\n%s\n", tc.reason, diff)
			}
			if diff := cmp.Diff(tc.want.o, got); diff != "" {
				t.Errorf("\n%s\ne.Observe(...): -want, +got:\n%s\n", tc.reason, diff)
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
		"successfully update": {
			reason: "policy should be deleted successfully",
			fields: fields{
				clientBuilder: func(t *testing.T) clients.VaultClient {
					ctrl := gomock.NewController(t)
					sysMock := fake.NewMockVaultSysClient(ctrl)
					sysMock.EXPECT().DeletePolicy(getTestPolicy().ObjectMeta.Name).Return(nil)

					client := fake.NewMockVaultClient(ctrl)
					client.EXPECT().Sys().Return(sysMock)
					return client
				},
			},
			args: args{
				ctx: context.TODO(),
				mg:  getTestPolicy(),
			},
			want: want{
				err: nil,
			},
		},
		"error creation": {
			reason: "error should be wrapped and bubbled up",
			fields: fields{
				clientBuilder: func(t *testing.T) clients.VaultClient {
					ctrl := gomock.NewController(t)
					sysMock := fake.NewMockVaultSysClient(ctrl)
					sysMock.EXPECT().DeletePolicy(getTestPolicy().ObjectMeta.Name).Return(nil)

					client := fake.NewMockVaultClient(ctrl)
					client.EXPECT().Sys().Return(sysMock)
					return client
				},
			},
			args: args{
				ctx: context.TODO(),
				mg:  getTestPolicy(),
			},
			want: want{
				err: nil,
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := &external{
				client: tc.fields.clientBuilder(t),
			}
			err := e.Delete(tc.args.ctx, tc.args.mg)
			if diff := cmp.Diff(tc.want.err, err, test.EquateErrors()); diff != "" {
				t.Errorf("\n%s\ne.Observe(...): -want error, +got error:\n%s\n", tc.reason, diff)
			}
		})
	}
}
