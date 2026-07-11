import httpx
import asyncio
import json

async def run():
    async with httpx.AsyncClient(timeout=60.0) as client:
        targets = [
            {"target": "wordpress.org", "target_type": "domain"},
            {"target": "reactjs.org", "target_type": "domain"},
            {"target": "8.8.8.8", "target_type": "ip"}
        ]
        
        for t in targets:
            print(f"=== Scanning {t['target']} ===")
            resp = await client.post('http://127.0.0.1:8000/scan', json=t)
            print(json.dumps(resp.json(), indent=2))
            print("\n")

asyncio.run(run())
