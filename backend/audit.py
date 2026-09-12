import asyncio
import os
from httpx import AsyncClient, ASGITransport
from app.main import app

async def run_audit():
    print("--- STARTING E2E AUDIT ---")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Health check
        res = await client.get("/api/v1/health")
        print("HEALTH:", res.status_code, res.json())
        
        # 2. Upload APK
        file_path = "tests/fixtures/dummy.apk"
        with open(file_path, "rb") as f:
            files = {"file": ("dummy.apk", f, "application/vnd.android.package-archive")}
            res = await client.post("/api/v1/samples/upload", files=files, data={"source": "audit"})
            print("UPLOAD:", res.status_code, res.json())
            
        if res.status_code != 200:
            print("Upload failed. Stopping.")
            return
            
        sample_id = res.json()["id"]
        
        # 3. Wait for pipeline
        print("Waiting for pipeline...")
        await asyncio.sleep(2)
        
        res = await client.get(f"/api/v1/samples/{sample_id}/status")
        print("STATUS:", res.status_code, res.json())
        
        res = await client.get(f"/api/v1/samples/{sample_id}/analysis")
        print("ANALYSIS:", res.status_code, res.json())

        res = await client.get(f"/api/v1/samples")
        print("SAMPLES LIST:", res.status_code, res.json())

if __name__ == "__main__":
    asyncio.run(run_audit())
