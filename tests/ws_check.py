import asyncio, json, pathlib
import websockets

CONFIG_PATH = pathlib.Path('data/publicnode_rpc_list.json')
with CONFIG_PATH.open() as f:
    cfg = json.load(f)

chains = cfg['chains']
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
