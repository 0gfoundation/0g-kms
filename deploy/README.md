# KMS deploy templates

Reference configuration for running a KMS cluster with monitoring. Every file here is a template —
fill in the `<...>` / `REGISTRY` / `TAG` placeholders for your environment. Nothing here contains
real hosts, IPs, or addresses.

## Layout

```
deploy/
├── docker-compose-tls.yml     per-node stack: kms + tls-init + nginx + alloy
├── config.alloy               alloy pipeline (reads the KMS log file, ships to Loki)
├── nginx.conf                 HTTPS reverse proxy (:9443 → kms:9090)
├── kms.toml.example           per-node KMS config (copy to kms.toml, fill in)
├── .env.example               operational env (copy to .env, set LOKI_URL)
└── monitoring/central/        the central machine: Prometheus + Loki + Grafana
    ├── docker-compose.yml
    ├── prometheus.yml          scrape targets (one per node) — fill in
    ├── alerts.yml              alert rules (one per SECURITY invariant)
    ├── loki-config.yml
    └── grafana/                provisioned datasources + dashboard
```

## Per-node stack

Each node runs `docker-compose-tls.yml`. Before deploying, place three files next to it:

- `kms.toml` — copy `kms.toml.example`, fill in this node's `self_url`, the peer `seeds`, chain,
  and app id. The config differs per node (each has its own `self_url`), so its hash is per-node.
- `config.alloy` — as-is.
- `.env` — copy `.env.example`, set `LOKI_URL` to the central Loki push endpoint.

The KMS writes structured logs both to stdout and to a file (`KMS_LOG_DIR=/var/log/kms`). The
`alloy` sidecar mounts that log dir **read-only** and ships it to `${LOKI_URL}`. It does not touch
the host docker socket, so it holds no host-container privilege, and needs no per-node label — each
log line carries `coordinator` (= own_id).

`.env` is mounted only so the deploy tool uploads it for `${LOKI_URL}` interpolation. That means its
value lands in the measured volumes hash, alongside `config.alloy` and `kms.toml`: deploying this
stack (or changing the Loki URL) moves the compose/volumes/image hashes, so refresh the on-chain
registration afterwards.

## Central machine

Runs on **one host that is not a KMS node**. Fill in `prometheus.yml` with each node's `:9090`
target (verify against the on-chain node list — a missing node is invisible, and invisible reads as
healthy), then:

```bash
cd monitoring/central
GRAFANA_PASSWORD=<pick one> docker compose up -d
```

The Loki port must be reachable by the KMS nodes (they push logs to it) and the Grafana port by
operators — open those in the host firewall / cloud security group.

The single dashboard shows the whole cluster (node detail is one table, not five dashboards). The
**P0 alert to watch is `kms_leading_holders < kms_recovery_threshold`**: below it a shardless node
can no longer rejoin while derives still succeed.
