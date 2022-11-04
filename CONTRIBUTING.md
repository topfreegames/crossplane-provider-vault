## Contributing

### Requirements
- go 1.18
- [gomplate](https://docs.gomplate.ca/)
- Docker

### Adding new Kind to the controller
- `GOMPLATE=gomplate KIND=your_kind GROUP=your_group PROVIDER=Vault hack/helpers/addtype.sh`
- Define your resource spec under `apis/<GROUP>/<KIND>_types.go`
- `make generate`
- Proper define the `Observe`, `Create`, `Update`, `Delete` methods in `internal/controller/<KIND>/<KIND>.go`
- Add your resource controller in the `Setup` method [here](internal/controller/vault.go).


### Testing locally
- First, you need to ensure you have docker running in the machine and you properly generated the CRDs following above steps, then run:
`make setup-dev-env` 
>This will spin up a kind cluster and setup a vault instance inside it. You can see the vault token in the output of this command
- To run the Controller locally, just run:
```make dev```
- To kill this environment, run `make dev-clean`
- To check the vault instance:
  - `kubectl port-forward --pod-running-timeout=30s -n vault service/vault 8200:8200`
  - `vault login`