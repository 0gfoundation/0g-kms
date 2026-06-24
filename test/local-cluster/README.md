# Local 3-node DPRF cluster test (S1)

End-to-end test of the threshold-BLS DPRF key-derivation path on a real 3-node KMS
cluster. Verifies the property S1 is about: app keys are derived by **combining partial
evaluations from ≥ threshold nodes, without any node ever reconstructing the master**.

This is **self-contained** — no real chain, no real TEE, no registry image:

- the image is **built from the current source** (Dockerfile), so it runs the new code;
- node signing keys come from `mock_tee` (the three standard Anvil accounts, injected via
  env);
- the on-chain `getNodeList(appId)` lookup is served by a tiny **mock JSON-RPC**
  (`mock-chain.py`) that returns the three node addresses.

## What it covers / does not cover

Covers (the part S1 changed):
- distributed partial collection over gRPC + in-group Lagrange combine (`collect_and_dprf`);
- determinism, appId-namespace isolation, derivation-material binding — across the real
  cluster, not just unit tests;
- threshold behaviour (k-of-n tolerance and sub-threshold failure).

Does **not** cover:
- shard **recovery** — deferred to S3; `recover_shard_for_caller` returns `unimplemented`.
  Joining nodes still get their shard via initial assignment, which this test exercises.
- the production TEE key source and real on-chain registry (mocked here by design).

## Prerequisites

- Docker + Docker Compose v2 (`docker compose ...`).
- A Rust toolchain on the host, to run the test client (`cargo`). The client reuses the
  repo's own `ecies`/`k256` crates so the ECIES response decrypts correctly — do **not**
  substitute an eciesjs/Python client (algorithm mismatch).

All commands below are run from `test/local-cluster/` unless noted.

## 1. Start the cluster

```bash
cd test/local-cluster
docker compose -f docker-compose.test.yml up --build -d
```

First run builds the image (compiles blst etc.) — several minutes. `kms2`/`kms3` may
restart a few times until `kms1` has bootstrapped; that is expected (they crash-loop on
"join failed" until the bootstrap node is ready, then succeed via `restart: unless-stopped`).

## 2. Wait for bootstrap + gossip convergence (~40–60s)

The coordinator collects partials from peers it learned via gossip (first round ~5s after
boot, then every 30s; full convergence typically ~60–90s). A derive call before its
coordinator knows ≥1 peer sees only the local partial and fails the threshold.

```bash
DC="docker compose -f docker-compose.test.yml"
# kms1 generated and split the master:
$DC logs kms1 | grep -i "Bootstrap node ready"
# kms2 / kms3 received their shard:
$DC logs kms2 | grep -i "Shard received"
$DC logs kms3 | grep -i "Shard received"
# the node you will QUERY (kms1) has registered its peers — this is the readiness gate.
# Expect ≥2 lines once kms2 and kms3 have gossiped in:
$DC logs kms1 | grep -i "gossip: peer registered"
```

Proceed once the first three greps print a line and the last prints ≥1. If a derive call
still returns `not enough partials`, gossip simply hasn't converged yet — wait ~30s and
retry; it is not a failure.

## 3. Run the derivation tests

The client prints the derived 32-byte app key as hex. The first `cargo run` compiles the
client (~1 min); subsequent runs are instant.

```bash
# from the repo root
cd ../..

# Caller = Anvil account #0 (must be in the mock nodeList — it is).
PRIV=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
N1=http://localhost:9101   # kms1
N2=http://localhost:9102   # kms2
N3=http://localhost:9103   # kms3

run() { cargo run -q --example dprf_client -- "$@"; }
```

### 3a. Determinism (same inputs → same key)

```bash
A=$(run $N1 0g-kms aabbccdd $PRIV)
B=$(run $N1 0g-kms aabbccdd $PRIV)
echo "A=$A"; echo "B=$B"
[ "$A" = "$B" ] && echo "PASS: deterministic" || echo "FAIL"
```

### 3b. Cross-node consistency (any coordinator → same key)

```bash
C=$(run $N2 0g-kms aabbccdd $PRIV)   # coordinated by kms2
D=$(run $N3 0g-kms aabbccdd $PRIV)   # coordinated by kms3
[ "$A" = "$C" ] && [ "$A" = "$D" ] && echo "PASS: node-independent" || echo "FAIL"
```

### 3c. Material binding (different material → different key)

```bash
E=$(run $N1 0g-kms 11111111 $PRIV)
[ "$A" != "$E" ] && echo "PASS: material-bound" || echo "FAIL"
```

### 3d. AppId namespace isolation (different app_id → different key)

```bash
F=$(run $N1 other-app aabbccdd $PRIV)
[ "$A" != "$F" ] && echo "PASS: namespace-isolated" || echo "FAIL"
```

## 4. Threshold behaviour

### 4a. Tolerates one node down (2 of 3 ≥ threshold=2)

```bash
docker compose -f test/local-cluster/docker-compose.test.yml stop kms3
# kms1 still lists kms3 as a peer (pruning takes 5 min), but the fetch to the dead node
# just fails and is skipped, leaving own + kms2 = 2 partials = threshold.
G=$(run $N1 0g-kms aabbccdd $PRIV)
[ "$A" = "$G" ] && echo "PASS: 2-of-3 still derives the same key" || echo "FAIL"
```

### 4b. Fails below threshold (1 of 3 < threshold=2)

```bash
docker compose -f test/local-cluster/docker-compose.test.yml stop kms2
sleep 35
# Expect a non-zero exit and an error mentioning "not enough partials".
run $N1 0g-kms aabbccdd $PRIV || echo "PASS: sub-threshold correctly refused"
```

Restart for further runs:

```bash
docker compose -f test/local-cluster/docker-compose.test.yml start kms2 kms3
```

## 5. Teardown

```bash
docker compose -f test/local-cluster/docker-compose.test.yml down -v
```

## Pass criteria (summary)

| Check | Expected |
|-------|----------|
| 3a determinism | A == B |
| 3b cross-node | A == C == D |
| 3c material | A != E |
| 3d appId | A != F |
| 4a 2-of-3 | A == G |
| 4b 1-of-3 | client errors with "not enough partials" |

## Troubleshooting

- **`not enough partials` right after startup** — gossip hasn't converged. Wait and retry
  (step 2). Confirm `self_url`/`seeds` in the `nodeX.toml` files match the compose service
  names.
- **`ECIES decrypt failed`** — only happens if a non-matching client is used. Use the
  provided `cargo run --example dprf_client`.
- **HTTP 401 / `not in on-chain signer list`** — the caller privkey's address isn't in the
  mock nodeList. Use one of the three Anvil keys (account #0 above).
- **`kms2`/`kms3` keep restarting** — normal until `kms1` bootstraps; check kms1 logs.
- **Inspect a node**: `docker compose -f docker-compose.test.yml logs -f kms1`.
