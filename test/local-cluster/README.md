# Local 3-node DKG cluster test

End-to-end test of the full threshold-BLS key lifecycle on a real 3-node KMS cluster:
**distributed genesis (no dealer) · app-key derivation · lost-share recovery · proactive
refresh · master consistency · threshold behaviour**. The master is threshold-shared and
**never reconstructed** on any node.

**Self-contained** — no real chain, no real TEE, no registry image:
- the image is **built from the current source** (Dockerfile), so it runs the new code;
- node keys come from `mock_tee` (the three standard Anvil accounts, injected via env);
- the on-chain `getNodeList(appId)` lookup is served by a tiny **mock JSON-RPC**
  (`mock-chain.py`) returning the three node addresses **in order** (order = participant id).

## Covers / does not cover

Covers: distributed genesis DKG (symmetric, no dealer), determinism / appId isolation /
material binding, threshold (k-of-n & sub-threshold), **reshare recovery**, **proactive
refresh**, and **master consistency** (group pubkey identical across nodes and across
recovery/refresh).

Does **not** cover (mocked by design): the **real on-chain registry** (`register-onchain`,
real `getNodeList`, stake/gas) and the **real TEE** key source (`mock_tee=false`). Those
require a real deployment (see `docs/CLUSTER.md`).

## Prerequisites
- Docker + Docker Compose v2.
- A Rust toolchain on the host for the test client. It reuses the repo's own `ecies`/`k256`
  crates so the ECIES response decrypts — do **not** substitute an eciesjs/Python client.

All commands run from `test/local-cluster/` unless noted. Helpers:
```bash
DC="docker compose -f docker-compose.test.yml"
strip(){ sed 's/\x1b\[[0-9;]*m//g'; }                 # strip tracing's ANSI colours
gp(){ $DC logs "$1" 2>&1 | strip | grep -o 'group_pubkey=[0-9a-f]*' | tail -1 | cut -d= -f2; }
PRIV=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80   # Anvil acct #0
N1=http://localhost:9101; N2=http://localhost:9102; N3=http://localhost:9103
run(){ cargo run -q --example dprf_client -- "$@"; }   # from the repo root
```

## 1. Start the cluster (distributed genesis, no dealer)
```bash
$DC up --build -d
```
First run builds the image (compiles blst + the DKG deps) — several minutes. All nodes start
symmetrically (no bootstrap node, no crash-loop): each starts its servers + gossip, waits for
full membership, then all three run the genesis DKG together.

## 2. Wait for genesis (~20–60s after gossip converges)
```bash
# genesis is done when all three log it (and the group pubkey is identical on all):
$DC logs kms1 | grep -i "genesis DKG complete"
$DC logs kms2 | grep -i "genesis DKG complete"
$DC logs kms3 | grep -i "genesis DKG complete"
```
Until genesis completes, `/app-key` returns *not ready*. If a derive returns
`not enough valid partials`, genesis/gossip just hasn't converged yet — wait and retry.

## 3. Derivation
```bash
cd ../..                        # client runs from repo root
A=$(run $N1 0g-kms aabbccdd $PRIV); echo "A=$A"
# 3a determinism:   run $N1 0g-kms aabbccdd $PRIV        → == A
# 3b cross-node:    run $N2 … ; run $N3 …                → == A
# 3c material:      run $N1 0g-kms 11111111 $PRIV        → != A
# 3d appId:         run $N1 other-app aabbccdd $PRIV     → != A
```

## 4. Master consistency (direct)
```bash
# genesis group pubkey must be byte-identical on all three nodes:
[ "$(gp kms1)" = "$(gp kms2)" ] && [ "$(gp kms1)" = "$(gp kms3)" ] \
  && echo "PASS: one master across the cluster"
```

## 5. Threshold behaviour
```bash
$DC stop kms3; sleep 3
[ "$(run $N1 0g-kms aabbccdd $PRIV)" = "$A" ] && echo "PASS: 2-of-3 derives the same key"

$DC stop kms2; sleep 3          # now 1 live share < threshold 2
run $N1 0g-kms aabbccdd $PRIV || echo "PASS: 1-of-3 refused (not enough valid partials)"
# NB: this drops below threshold → unrecoverable; restore with a fresh genesis:
$DC down; $DC up -d             # (wait for genesis again)
```

## 6. Recovery + disaster gate (restart a node → auto-recover, never a new master)
```bash
A=$(run $N1 0g-kms aabbccdd $PRIV)            # baseline (all 3 up)
G0=$(gp kms1)
$DC restart kms3                              # kms3 loses its in-memory share
# kms3 sees the cluster is established, refuses to regenerate a master, and recovers via reshare:
$DC logs --since 3m kms3 | grep -i "reshare recovery complete"
# no new master was minted, and the group pubkey is unchanged:
[ "$(gp kms3)" = "$G0" ] && echo "PASS: master preserved (no regeneration)"
[ "$(run $N1 0g-kms aabbccdd $PRIV)" = "$A" ] && echo "PASS: cluster still derives the original key"
```

## 7. Proactive refresh (rotate shares, preserve master)
```bash
A=$(run $N1 0g-kms aabbccdd $PRIV); G0=$(gp kms1)
curl -s -X POST $N1/refresh; echo            # → "refresh complete"
$DC logs --since 2m | grep -c "reshare dealer complete"   # → 3
[ "$(run $N1 0g-kms aabbccdd $PRIV)" = "$A" ] && [ "$(gp kms1)" = "$G0" ] \
  && echo "PASS: refresh preserved the master (key + pubkey unchanged); shares rotated"
```

## 8. Teardown
```bash
$DC down -v
```

## Pass criteria (summary)
| Check | Expected |
|---|---|
| genesis | all 3 log `genesis DKG complete`, identical `group_pubkey` |
| 3 derivation | determinism / cross-node ==; material / appId != |
| 4 master consistency | group pubkey identical across nodes |
| 5 threshold | 2-of-3 == baseline; 1-of-3 errors `not enough valid partials` |
| 6 recovery | `reshare recovery complete`; pubkey unchanged; key unchanged |
| 7 refresh | `refresh complete`; key + pubkey unchanged |

## Troubleshooting
- **`not enough valid partials` right after startup** — genesis/gossip hasn't converged; wait
  and retry. Confirm `self_url`/`seeds` in `nodeX.toml` match the compose service names.
- **`ECIES decrypt failed`** — a non-matching client was used; use `cargo run --example dprf_client`.
- **HTTP 401 / not in signer list** — caller address isn't in the mock nodeList; use an Anvil key.
- **A node stays without a share** — it couldn't recover (fewer than `threshold` live shares);
  restore with a fresh genesis (`$DC down; $DC up -d`).
- **Inspect a node**: `$DC logs -f kms1`.
