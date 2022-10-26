#!/bin/bash

set -v -e

trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

# The vault pod will only be ready once vault is unsealed.
kubectl wait --for=condition=Initialized pod/vault-0 -n vault
sleep 10
kubectl port-forward --pod-running-timeout=30s -n vault service/vault 8200:8200 &
pid=$!
echo pid: $pid

# kill the port-forward regardless of how this script exits
trap 'kill ${pid}' SIGINT SIGTERM EXIT

while ! nc -z localhost 8200; do   
  sleep 0.1 # wait for 1/10 of the second before check again
done

export VAULT_ADDR=http://localhost:8200
credentials=$(vault operator init -format=json)

for i in {0..2}; do
  key=$(echo $credentials | jq .unseal_keys_b64[$i] | tr -d '"')
  vault operator unseal $key
done

token=$(echo $credentials | jq .root_token | tr -d '"')
echo "vault_token: ${token}"
vault login $token

kubectl create ns crossplane-system 2&>1
kubectl create secret generic provider-vault-secret --namespace=crossplane-system --from-literal credentials=$token