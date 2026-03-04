import asyncio
import json
import os
import pathlib
import sys

import websockets


def load_dotenv(path: pathlib.Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def load_chains() -> dict[str, dict[str, str]]:
    config_override = os.environ.get("WS_CHECK_CONFIG")
    if config_override:
        config_path = pathlib.Path(config_override)
        if not config_path.exists():
            print(f"missing config file: {config_path}", file=sys.stderr)
            sys.exit(2)
        with config_path.open() as f:
            cfg = json.load(f)
        chains = cfg.get("chains", {})
        if not isinstance(chains, dict) or not chains:
            print("WS_CHECK_CONFIG file has no usable 'chains' object", file=sys.stderr)
            sys.exit(2)
        return chains

    env = load_dotenv(pathlib.Path(".env"))
    merged = {**env, **os.environ}
    chains: dict[str, dict[str, str]] = {}
    for key, value in merged.items():
        if not value:
            continue
        if key == "WEBSOCKET_PROVIDER":
            chains["default"] = {"ws": value}
            continue
        prefix = "WEBSOCKET_PROVIDER_"
        if key.startswith(prefix):
            chain_id = key[len(prefix):]
            if chain_id:
                chains[chain_id] = {"ws": value}

    if not chains:
        print(
            "No websocket providers found. Set WEBSOCKET_PROVIDER_<chain_id> in .env or env.",
            file=sys.stderr,
        )
        print(
            "Optionally set WS_CHECK_CONFIG to a JSON file shaped like {'chains': {'name': {'ws': 'wss://...'}}}.",
            file=sys.stderr,
        )
        sys.exit(2)
    return chains


chains = load_chains()
actions = [
    ("newHeads", ["newHeads"]),
    ("logs", ["logs", {}]),
    ("newPendingTransactions", ["newPendingTransactions"]),
]

async def recv_for_id(ws, req_id, max_messages=6):
    for _ in range(max_messages):
        resp = await asyncio.wait_for(ws.recv(), timeout=3)
        data = json.loads(resp)
        if data.get('id') == req_id:
            if 'result' in data:
                return 'ok', data['result']
            return 'err', data.get('error')
    return 'err', 'no matching response'

async def probe(name, url):
    results = {}
    try:
        async with websockets.connect(url, max_size=2**20, ping_interval=20, close_timeout=2) as ws:
            req_id = 1
            for label, params in actions:
                req = {"id": req_id, "jsonrpc": "2.0", "method": "eth_subscribe", "params": params}
                await ws.send(json.dumps(req))
                try:
                    status, detail = await recv_for_id(ws, req_id)
                except Exception as e:
                    status, detail = 'timeout', str(e)
                results[label] = (status, detail)
                req_id += 1
            await ws.close()
    except Exception as e:
        results['connect'] = ('fail', str(e))
    return name, results

async def main():
    tasks = [probe(name, info['ws']) for name, info in chains.items()]
    results = await asyncio.gather(*tasks)
    for name, res in results:
        print(f"=== {name} ===")
        for k, v in res.items():
            status, detail = v
            print(f"{k}: {status} {detail}")
        print()

if __name__ == '__main__':
    asyncio.run(main())
