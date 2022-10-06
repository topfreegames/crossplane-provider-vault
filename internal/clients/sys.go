package clients

type VaultSysClient interface {
	GetPolicy(name string) (string, error)
	PutPolicy(name string, rules string) error
	DeletePolicy(name string) error
}

func (vc *VaultClientWrapper) Sys() VaultSysClient {
	return vc.Client.Sys()
}
