package clients

//go:generate go run github.com/golang/mock/mockgen  --build_flags=--mod=mod -package fake -copyright_file ../../hack/boilerplate.go.txt -destination ./fake/zz_generated.fake.go github.com/topfreegames/crossplane-provider-vault/internal/clients VaultClient,VaultSysClient

import (
	_ "github.com/golang/mock/mockgen/model" //nolint:typecheck
)
