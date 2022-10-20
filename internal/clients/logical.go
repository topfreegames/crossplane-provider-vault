package clients

import (
	vault "github.com/hashicorp/vault/api"
)

// VaultLogicalClient is the interface that wraps the vault Logical subclient
type VaultLogicalClient interface {
	Write(path string, data map[string]interface{}) (*vault.Secret, error)
	Delete(path string) (*vault.Secret, error)
	Read(path string) (*vault.Secret, error)
}

// Logical returns the vault logical for write usage
func (vc *VaultClientWrapper) Logical() VaultLogicalClient {
	return vc.Client.Logical()
}
