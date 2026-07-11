import httpx
import asyncio
import json

async def run():
    resp = await httpx.AsyncClient().post(
        'http://127.0.0.1:8000/scan',
        json={'target': '8.8.8.8', 'target_type': 'ip'},
        timeout=30
    )
    print(json.dumps(resp.json(), indent=2))

asyncio.run(run())
