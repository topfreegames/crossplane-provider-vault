package clients

// VaultSysClient is the interface that wraps the vault Sys subclient
type VaultSysClient interface {
	GetPolicy(name string) (string, error)
	PutPolicy(name string, rules string) error
	DeletePolicy(name string) error
}

// Sys returns the vault sys subclient
func (vc *VaultClientWrapper) Sys() VaultSysClient {
	return vc.Client.Sys()
}
