#!/usr/bin/env python3
"""Minimal mock JSON-RPC endpoint for local KMS cluster tests.

The KMS auth layer (both inter-node and the HTTP /app-key handler) calls
`getNodeList(appId) -> address[]` on a TappRegistry contract. For a self-contained
local test we don't want a real chain, so this server answers every `eth_call` with a
fixed `address[]` of the three test nodes, regardless of the call target or appId.

stdlib only — run with: python3 mock-chain.py  (listens on 0.0.0.0:8545)
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

# The three node addresses, IN ORDER. Order matters: it is the on-chain nodeList order,
# which the bootstrap node uses to assign shards by position (index 0 -> node1, etc.).
# These are the standard Anvil/Hardhat deterministic accounts #0, #1, #2.
NODE_ADDRESSES = [
    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",  # acc0  -> kms1 (bootstrap)
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",  # acc1  -> kms2
    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",  # acc2  -> kms3
]

CHAIN_ID = "0x40d9"  # 16601 (0G testnet); any value is fine for the mock


def encode_address_array(addrs):
    """ABI-encode a dynamic address[] as an eth_call return value."""
    words = []
    words.append((32).to_bytes(32, "big").hex())        # offset to the array data
    words.append(len(addrs).to_bytes(32, "big").hex())  # array length
    for a in addrs:
        clean = a.lower().replace("0x", "")
        words.append(clean.rjust(64, "0"))              # left-padded 20-byte address
    return "0x" + "".join(words)


RESULT_GET_NODE_LIST = encode_address_array(NODE_ADDRESSES)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # quiet

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        try:
            req = json.loads(raw)
        except Exception:
            self._send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
            return

        # Support JSON-RPC batches and single calls.
        if isinstance(req, list):
            self._send([self._handle_one(r) for r in req])
        else:
            self._send(self._handle_one(req))

    def _handle_one(self, r):
        method = r.get("method", "")
        rid = r.get("id")
        if method == "eth_call":
            result = RESULT_GET_NODE_LIST
        elif method == "eth_chainId":
            result = CHAIN_ID
        elif method == "net_version":
            result = str(int(CHAIN_ID, 16))
        elif method == "eth_blockNumber":
            result = "0x1"
        else:
            result = "0x"
        print(f"[mock-chain] {method} -> {result[:18]}{'...' if len(result) > 18 else ''}", flush=True)
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    def _send(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    print(f"[mock-chain] getNodeList -> {NODE_ADDRESSES}", flush=True)
    HTTPServer(("0.0.0.0", 8545), Handler).serve_forever()
