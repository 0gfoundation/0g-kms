# 0g-kms testnet end-to-end test (real TEE + on-chain)

End-to-end validation of the threshold-BLS DKG cluster on **real TDX TEE nodes** registered
on the **0G testnet** — as opposed to the self-contained mock harness in
[`test/local-cluster/`](../test/local-cluster/README.md) (mock chain + mock TEE).

Scope validated: distributed genesis · app-key derivation (determinism, cross-node, material
and appId isolation, authorization) · proactive refresh · reshare recovery (including a node
rejoining on a changed port) · node replacement with a new TEE identity (on-chain
remove + re-add).

## Topology

| | Value |
|---|---|
| Nodes | 3 TDX servers, one KMS container each |
| app_id | `0g-kms-test` |
| Registry contract | `0x2ce80374318b1d7fb3345724457a182e0ad165c9` |
| Chain | 0G testnet — RPC `https://evmrpc-testnet.0g.ai`, chainId `16602` |
| Threshold | 2-of-3 |
| Ports (per host) | HTTP `9095` (`/app-key`, `/refresh`), inter-node gRPC `9093` |
| Image | `…/eliza/0g-kms:dev` (`pull_policy: always`) |

Each host runs `docker-compose-test.yml`, which mounts that host's config from the ephemeral
slot `kms-deploy.toml`. Per-node configs differ only in `self_url` (its own `<ip>:9093`) and
`seeds` (node 1 empty; nodes 2/3 point at node 1).

## Prerequisites

- `tapp-cli`, `cast` (foundry), and the `dprf_client` example built (`cargo build --example dprf_client`).
- The `:dev` image built and pushed to the registry.
- A funded key that is the **app owner** on-chain and authorized on each tapp server
  (referred to below as `$DEPLOY_KEY`). Convert to address with `cast wallet address`.
- Each node already registered on-chain (`getNodeList 0g-kms-test` returns 3 signer addresses).

Helpers used below:
```bash
C=0x2ce80374318b1d7fb3345724457a182e0ad165c9
R=https://evmrpc-testnet.0g.ai
N1=http://47.84.230.10:9095 ; N2=http://8.222.225.233:9095 ; N3=http://47.236.111.154:9095
cast(){ docker run --rm --entrypoint cast ghcr.io/foundry-rs/foundry:latest "$@"; }
run(){ ./target/debug/examples/dprf_client "$@"; }   # <node_http> <app_id> <material_hex> <priv>
gp(){ tapp-cli -s http://$1:50051 -k $DEPLOY_KEY get-app-logs --app-id 0g-kms-test --service kms -n 200 \
      | sed 's/\x1b\[[0-9;]*m//g' | grep -o 'group_pubkey=[0-9a-f]*' | tail -1; }
```

## 1. Deploy

On each host, log the tapp server into the registry, place that node's config in the deploy
slot, and start the app:

```bash
tapp-cli -s http://<host>:50051 -k $DEPLOY_KEY docker-login \
  -r <registry-host> -u <user> -p "$REGISTRY_TOKEN"
cp kms-<node>-test.toml kms-deploy.toml
tapp-cli -s http://<host>:50051 -k $DEPLOY_KEY start-app \
  -f docker-compose-test.yml --app-id 0g-kms-test
```

Do the three hosts in any order; the nodes wait for full membership and then run genesis
together. `start-app` is async — poll `get-task-status` until `Completed`.

## 2. Genesis

Genesis is complete when all three nodes log it with a **byte-identical** group public key:

```bash
for h in 47.84.230.10 8.222.225.233 47.236.111.154; do
  tapp-cli -s http://$h:50051 -k $DEPLOY_KEY get-app-logs --app-id 0g-kms-test --service kms -n 80 \
    | sed 's/\x1b\[[0-9;]*m//g' | grep -i 'genesis DKG complete'
done
```

The master scalar is never reconstructed; only the group public key (`g^master`) is recorded.

## 3. Authorization model (needed for derivation tests)

`/app-key` authenticates the caller by recovering its address from an EIP-191 signature and
requiring it to be in the **on-chain signer list of the requested `app_id`**. The three KMS
node signers are TEE-derived (their private keys live in the TEE and cannot be signed with
externally).

To exercise derivation, register a throwaway consumer app whose signer is a key you hold, and
request that app_id. The KMS derives a key for **any** app_id (bound into `H(bind(app_id,
material))`); the signer check just gates who may request it.

```bash
DERIVE_ADDR=$(cast wallet address $DERIVE_KEY)
cast send "$C" "registerApp(string,bytes,bytes,bytes[],address,string)" \
  "kms-derive-probe" 0x 0x "[]" "$DERIVE_ADDR" "http://probe:0" \
  --value 1000000000000000000 --rpc-url "$R" --private-key $DEPLOY_KEY --legacy --gas-price 3000000000
```

For the appId-isolation check, register a **second** probe app (`kms-derive-probe2`) the same way.

## 4. Derivation

The client signs with `$DERIVE_KEY` (whose address is the probe app's signer) and ECIES-decrypts
the response, printing the 32-byte app key as hex.

```bash
A=$(run $N1 kms-derive-probe aabbccdd $DERIVE_KEY)   # baseline
```

| Check | Command | Expected |
|---|---|---|
| Determinism | `run $N1 kms-derive-probe aabbccdd $DERIVE_KEY` | == `A` |
| Cross-node | `run $N2 …` ; `run $N3 …` | == `A` |
| Material isolation | `run $N1 kms-derive-probe 11111111 $DERIVE_KEY` | != `A` |
| appId isolation | `run $N1 kms-derive-probe2 aabbccdd $DERIVE_KEY` | != `A` |
| Negative auth | `run $N1 0g-kms-test aabbccdd $DERIVE_KEY` | HTTP 401 (not in signer list) |

Cross-node equality proves a single master with in-group Lagrange combine; the isolation
checks prove both `app_id` and `material` bind into the derivation.

## 5. Proactive refresh

```bash
G0=$(gp 47.84.230.10)                       # baseline group pubkey
curl -s -X POST $N1/refresh                 # -> "refresh complete"
```

Verify on all three nodes:
```bash
for h in 47.84.230.10 8.222.225.233 47.236.111.154; do
  tapp-cli -s http://$h:50051 -k $DEPLOY_KEY get-app-logs --app-id 0g-kms-test --service kms -n 60 \
    | sed 's/\x1b\[[0-9;]*m//g' | grep -i 'reshare dealer complete'
done
```

Pass: all three log `reshare dealer complete — share refreshed, master preserved`; group pubkey
unchanged (`gp` == `G0` on every node); re-deriving returns `A`. Shares rotate onto a new
polynomial with the same intercept — previously-leaked shares expire, master and derived keys
are unchanged.

## 6. Reshare recovery (node restart, including a changed port)

Restart a node; it loses its in-memory share, sees the cluster is already established, and
repairs its share via reshare — it never regenerates a master (disaster gate).

```bash
tapp-cli -s http://47.236.111.154:50051 -k $DEPLOY_KEY stop-app  --app-id 0g-kms-test
# (optionally change the inter-node port in kms-deploy.toml + the compose before restart)
tapp-cli -s http://47.236.111.154:50051 -k $DEPLOY_KEY start-app -f docker-compose-test.yml --app-id 0g-kms-test
```

Pass: the node logs `reshare recovery complete — share repaired, master preserved`; its group
pubkey equals `G0`; the cluster still derives `A`. If the node comes back on a different
`self_url`, cluster formation retries until gossip reconverges on the new address — recovery
still succeeds (peer table is keyed by node identity, not URL).

## 7. Node replacement (new TEE identity)

Replace a node with a fresh TEE identity (e.g. a redeployed host). A tapp daemon restart mints
a new node signer, so the on-chain node list must be updated to match.

```bash
# 1. stop the KMS app on the target host
tapp-cli -s http://<host>:50051 -k $DEPLOY_KEY stop-app --app-id 0g-kms-test
# 2. restart the tapp daemon on that host (host operation) -> new TEE identity
# 3. read the new signer
NEW=$(tapp-cli -s http://<host>:50051 -k $DEPLOY_KEY get-app-key --app-id 0g-kms-test \
        | grep -o '0x[0-9a-fA-F]\{40\}')
# 4. remove the old (now-dead) signer on-chain (starts the stake-lock period)
tapp-cli -s http://<any-owned-host>:50051 -k $DEPLOY_KEY remove-node-onchain \
  --app-id 0g-kms-test --rpc-url $R --contract $C --signer-address <OLD_SIGNER>
# 5. re-login the registry, then start with --register-onchain:
#    idempotently addNode(NEW) before the container starts
tapp-cli -s http://<host>:50051 -k $DEPLOY_KEY docker-login -r <registry-host> -u <user> -p "$REGISTRY_TOKEN"
tapp-cli -s http://<host>:50051 -k $DEPLOY_KEY start-app -f docker-compose-test.yml --app-id 0g-kms-test \
  --register-onchain --rpc-url $R --contract $C --stake-wei 1000000000000000000
```

Pass: `getNodeList` shows the new signer in the replaced node's slot; the new node logs
`reshare recovery complete — share repaired, master preserved` with group pubkey `G0`; the
cluster derives `A` across all three nodes. The replacement runs the same reshare path as a
restart — the participant set is anchored on the on-chain node list, so the retired identity
does not interfere.

Notes:
- Use `update-node-onchain` / `remove` + `--register-onchain` — not `registerApp` (the app
  already exists) and not `add-node-onchain` without measurement (leaves the per-node volume
  hash inheriting the app default).
- `remove-node-onchain` locks the removed node's stake for the contract's lock period;
  reclaim later with `withdraw --signer-address <OLD_SIGNER>`.

## Pass criteria (summary)

| # | Check | Expected |
|---|---|---|
| 2 | Genesis | all 3 log `genesis DKG complete`, identical group pubkey |
| 4 | Derivation | determinism / cross-node ==; material / appId !=; unauthorized app_id -> 401 |
| 5 | Refresh | all 3 `reshare dealer complete`; group pubkey + derived key unchanged |
| 6 | Recovery | `reshare recovery complete`; group pubkey + derived key unchanged (incl. port change) |
| 7 | Replacement | node list updated to new signer; new identity recovers; group pubkey + derived key unchanged |

## Cleanup

- Stop the probe apps' stake reclaim: each `registerApp`/`add-node` staked `minStakeAmount`
  (1 0G). Remove the node/app and `withdraw` after the stake-lock period to reclaim.
- `kms-deploy.toml` is an ephemeral, gitignored deploy slot; the real per-node configs
  (`kms-*-test.toml`) are never overwritten.
