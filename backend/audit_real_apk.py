import asyncio
import os
import json
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.db.database import AsyncSessionLocal, engine, Base
from sqlalchemy import text

async def run_real_audit():
    print("--- STARTING REAL E2E AUDIT ---")
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        await db.execute(text("DELETE FROM sample_campaign_links"))
        await db.execute(text("DELETE FROM findings"))
        await db.execute(text("DELETE FROM analyses"))
        await db.execute(text("DELETE FROM campaigns"))
        await db.execute(text("DELETE FROM samples"))
        await db.commit()

    file_path = "tests/fixtures/ApiDemos-debug.apk"
    if not os.path.exists(file_path):
        print("ERROR: Test APK not found!")
        return

    # Use uvicorn server running in a background process, or just use ASGITransport
    # With ASGITransport background tasks run synchronously at the end of the request.
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Upload APK
        print("\n--- STEP 2: REAL UPLOAD ---")
        with open(file_path, "rb") as f:
            files = {"file": ("ApiDemos-debug.apk", f, "application/vnd.android.package-archive")}
            res = await client.post("/api/v1/samples/upload", files=files, data={"source": "real_audit"})
            print(f"UPLOAD STATUS: {res.status_code}")
            
        sample = res.json()
        sample_id = sample["id"]
        print(f"SAMPLE ID: {sample_id}")
        
        # 5 & 7. CORRELATION & CAMPAIGN
        print("\n--- STEP 5 & 7: CORRELATION ---")
        print("Copying APK to simulate a second submission with the same certificate...")
        with open("tests/fixtures/ApiDemos-debug2.apk", "wb") as f_out:
            with open(file_path, "rb") as f_in:
                data = f_in.read()
                f_out.write(data + b"junk123456789")
                
        with open("tests/fixtures/ApiDemos-debug2.apk", "rb") as f:
            files = {"file": ("ApiDemos-debug2.apk", f, "application/vnd.android.package-archive")}
            res2 = await client.post("/api/v1/samples/upload", files=files, data={"source": "real_audit2"})
            print(f"UPLOAD 2 STATUS: {res2.status_code}")
            
        sample2_id = res2.json()["id"]
        print(f"SAMPLE 2 ID: {sample2_id}")

        # Check Campaigns
        camp_res = await client.get("/api/v1/campaigns")
        campaigns = camp_res.json()
        print(f"TOTAL CAMPAIGNS: {campaigns['total']}")
        
        if campaigns['total'] > 0:
            c_id = campaigns['items'][0]['id']
            graph_res = await client.get(f"/api/v1/campaigns/{c_id}/graph")
            print("GRAPH:", json.dumps(graph_res.json(), indent=2))
            
if __name__ == "__main__":
    asyncio.run(run_real_audit())
