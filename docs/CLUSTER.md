# 0g-kms cluster: lifecycle & API

How the KMS cluster forms and operates: **init (genesis) · join · rejoin/recovery · request
a key · authentication · refresh**. The master signing key is threshold-shared and **never
reconstructed** on any node; app keys are derived by a threshold-BLS DPRF.

## Concepts

- **nodeList** — the ordered list of node addresses returned by `getNodeList(appId)` on the
  TappRegistry contract. A node's **participant id** is its 1-based position in this list; it
  is also the source of truth for who may participate and who may call.
- **share** — each node holds one Shamir share of the master (in-memory only; see *Rejoin*).
- **group public key** — `master·G` (G1), identical on every node; the "genesis happened"
  witness (logged as `group_pubkey=…`).
- **threshold `t` of `n`** — any `t` shares derive; `< t` cannot. Recovery needs ≥`t` live
  shares.

Config (`kms.toml`):
```toml
[server]  bind = "0.0.0.0:9090"      # HTTP (/app-key, /refresh)
          grpc_bind = "0.0.0.0:9092" # inter-node
          timestamp_tolerance_secs = 300
[tapp]    app_id = "0g-kms"          # namespace; must match on-chain
[chain]   rpc_url = "..."            # reads getNodeList(app_id)
          contract_address = "0x..."
[cluster] threshold = 2
          total_nodes = 3
          self_url = "http://nodeX:9092"   # this node's gRPC URL as peers see it
          seeds = ["http://nodeY:9092", …] # initial gossip contacts
          # bootstrap = …  # LEGACY / ignored (genesis is now symmetric DKG)
```

## 1. Init (genesis)

Genesis is a **distributed DKG with no dealer** — no node ever holds the master.

1. Register the `n` node addresses in the on-chain nodeList for `app_id`.
2. Start all `n` nodes (order doesn't matter). Each starts its HTTP + gRPC servers and gossip.
3. Each node waits for **full membership** (all nodeList members discovered via gossip, with
   their pubkeys), then probes peers: if none is initialized → **fresh cluster** → all nodes
   run the 5-round DKG together (`genesis:{app_id}` session).
4. On completion each node stores its share and the group pubkey (logs
   `genesis DKG complete … group_pubkey=…` — identical on all nodes).

Until genesis completes, `/app-key` returns *not ready*. No manual trigger; nodes converge on
their own (seconds after gossip converges).

## 2. Join (a node joining an already-established cluster)

Adding a node to a live cluster = the recovery path (there is no separate "pull a shard"):
1. Add the new node's address to the on-chain nodeList.
2. Start the node. It discovers the cluster via gossip, sees the cluster is **established**,
   and runs a **reshare** to obtain a consistent share (it joins the session as a
   `RefreshParticipant`; existing members act as dealers). Master unchanged.
3. Done when it logs `reshare recovery complete`. It now serves/participates normally.

## 3. Rejoin / recovery (a node lost its share)

Shares are **in-memory** (TEE model — deliberately no disk persistence, so a compromised disk
never yields a share). A restarted / redeployed node has no share and recovers automatically:

1. On boot it finds the cluster **established** (peers hold shares).
2. **Disaster gate:** it will **never regenerate a master**. It triggers a reshare and rejoins
   as a `RefreshParticipant`; survivors reshare their shares (`StartReshare` → dealer side),
   preserving the master.
3. Done when it logs `reshare recovery complete`; the group pubkey is unchanged.

If fewer than `t` nodes still hold shares, recovery is impossible (inherent to threshold
sharing) — the node fails loudly rather than corrupting the cluster. Recover promptly after
each loss; don't let live shares fall to `t-1`.

## 4. Request an app key

`POST /app-key` (HTTP, to any node — that node coordinates the threshold derivation):
```json
{
  "app_id":    "0g-kms",
  "timestamp": 1730000000,
  "pubkey":    "<hex uncompressed secp256k1, 65 bytes>",
  "signature": "<hex EIP-191 personal_sign, 65 bytes r||s||v>",
  "material":  "<hex, optional>"   // bound into the key alongside app_id
}
```
- The signature is an **EIP-191 `personal_sign`** over `"GetSecretResource:{timestamp}"`.
- Response: `{ "encrypted_secret": "<hex ECIES(app_key)>" }` — a 32-byte app key encrypted to
  the caller's `pubkey`; decrypt with the matching secp256k1 private key.
- Deterministic: same `(app_id, material)` → same key, from any coordinator. Different
  `app_id` or `material` → different key.

Reference client: `cargo run --example dprf_client -- <node_url> <app_id> <material_hex> <priv_hex>`
(uses the repo's own `ecies`/`k256` so the response decrypts correctly).

## 5. Authentication

**Client → `/app-key`:** the request signature is recovered to an address, which must be in
the on-chain `getNodeList(app_id)` signer list; `timestamp` must be within
`timestamp_tolerance_secs` (±300s). The reply is ECIES-encrypted to the caller's pubkey.

**Node → node (all gRPC RPCs):** every call carries metadata `signature` + `timestamp`, where
`signature` is a recoverable secp256k1 signature over `"kms:{method}:{timestamp}"`. The
responder recovers the caller's address, checks the timestamp window, and verifies the caller
is in the on-chain nodeList. Payloads (partials, shares, DKG round-1 p2p) are ECIES-encrypted
to the recipient. Identity is anchored on the on-chain nodeList — no shared secrets.

## 6. Refresh (proactive resharing)

`POST /refresh` (to any node) triggers a **committee-wide reshare**: every node reshares its
existing share (all as dealers, no membership change) onto a fresh polynomial with the **same
intercept**. Result: all shares are re-randomized, so any previously-leaked share becomes
useless (proactive security), while the master and every derived app key are unchanged (group
pubkey byte-identical before/after).

Run it periodically (e.g. per epoch) to bound the window in which an attacker must collect
`≥t` shares. Recovery (§3) and refresh share the same machinery.

> ⚠️ In this build `/refresh` is unauthenticated (test harness). Production must gate it
> (operator auth / on-chain policy). Likewise, avoid running a derive concurrently with a
> reshare/refresh until derivations are quiesced during resharing (see PR follow-ups).

## Endpoints & ports (summary)

| Endpoint | Where | Purpose |
|---|---|---|
| `POST /app-key` | HTTP (`server.bind`) | derive an app key (client-authenticated) |
| `POST /refresh` | HTTP (`server.bind`) | proactive committee-wide reshare |
| `KmsCluster` gRPC | `server.grpc_bind` | inter-node: DPRF partials, DKG/reshare rounds, gossip |

See `test/local-cluster/` for a runnable 3-node example (mock chain + mock TEE keys).
