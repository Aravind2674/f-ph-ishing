import asyncio
from app.ingestion.techfingerprint import TechFingerprintClient

async def main():
    client = TechFingerprintClient(use_mock=False)
    res = await client.fingerprint_url('https://sairam.edu.in')
    print("Technologies:")
    for t in res.technologies:
        print(t.name)
    await client.close()

asyncio.run(main())
