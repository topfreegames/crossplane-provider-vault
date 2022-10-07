// /*
// Copyright 2020 The Crossplane Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// */

// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/topfreegames/crossplane-provider-vault/internal/clients (interfaces: VaultClient,VaultSysClient)

// Package fake is a generated GoMock package.
package fake

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	clients "github.com/topfreegames/crossplane-provider-vault/internal/clients"
)

// MockVaultClient is a mock of VaultClient interface.
type MockVaultClient struct {
	ctrl     *gomock.Controller
	recorder *MockVaultClientMockRecorder
}

// MockVaultClientMockRecorder is the mock recorder for MockVaultClient.
type MockVaultClientMockRecorder struct {
	mock *MockVaultClient
}

// NewMockVaultClient creates a new mock instance.
func NewMockVaultClient(ctrl *gomock.Controller) *MockVaultClient {
	mock := &MockVaultClient{ctrl: ctrl}
	mock.recorder = &MockVaultClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockVaultClient) EXPECT() *MockVaultClientMockRecorder {
	return m.recorder
}

// Sys mocks base method.
func (m *MockVaultClient) Sys() clients.VaultSysClient {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Sys")
	ret0, _ := ret[0].(clients.VaultSysClient)
	return ret0
}

// Sys indicates an expected call of Sys.
func (mr *MockVaultClientMockRecorder) Sys() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Sys", reflect.TypeOf((*MockVaultClient)(nil).Sys))
}

// MockVaultSysClient is a mock of VaultSysClient interface.
type MockVaultSysClient struct {
	ctrl     *gomock.Controller
	recorder *MockVaultSysClientMockRecorder
}

// MockVaultSysClientMockRecorder is the mock recorder for MockVaultSysClient.
type MockVaultSysClientMockRecorder struct {
	mock *MockVaultSysClient
}

// NewMockVaultSysClient creates a new mock instance.
func NewMockVaultSysClient(ctrl *gomock.Controller) *MockVaultSysClient {
	mock := &MockVaultSysClient{ctrl: ctrl}
	mock.recorder = &MockVaultSysClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockVaultSysClient) EXPECT() *MockVaultSysClientMockRecorder {
	return m.recorder
}

// DeletePolicy mocks base method.
func (m *MockVaultSysClient) DeletePolicy(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeletePolicy", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeletePolicy indicates an expected call of DeletePolicy.
func (mr *MockVaultSysClientMockRecorder) DeletePolicy(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeletePolicy", reflect.TypeOf((*MockVaultSysClient)(nil).DeletePolicy), arg0)
}

// GetPolicy mocks base method.
func (m *MockVaultSysClient) GetPolicy(arg0 string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPolicy", arg0)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPolicy indicates an expected call of GetPolicy.
func (mr *MockVaultSysClientMockRecorder) GetPolicy(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPolicy", reflect.TypeOf((*MockVaultSysClient)(nil).GetPolicy), arg0)
}

// PutPolicy mocks base method.
func (m *MockVaultSysClient) PutPolicy(arg0, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PutPolicy", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// PutPolicy indicates an expected call of PutPolicy.
func (mr *MockVaultSysClientMockRecorder) PutPolicy(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PutPolicy", reflect.TypeOf((*MockVaultSysClient)(nil).PutPolicy), arg0, arg1)
}