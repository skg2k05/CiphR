import asyncio
from unittest.mock import patch
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.db.database import AsyncSessionLocal, engine, Base
from sqlalchemy import text

async def run_success_audit():
    print("--- STARTING SUCCESS E2E AUDIT ---")
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Clean DB
    async with AsyncSessionLocal() as db:
        await db.execute(text("DELETE FROM sample_campaign_links"))
        await db.execute(text("DELETE FROM findings"))
        await db.execute(text("DELETE FROM analyses"))
        await db.execute(text("DELETE FROM campaigns"))
        await db.execute(text("DELETE FROM samples"))
        await db.commit()
    
    # We patch analyze_apk_static to bypass the malformed dummy apk error
    with patch("app.services.pipeline_service.analyze_apk_static") as mock_analyze:
        mock_analyze.return_value = {
            "status": "COMPLETED",
            "package_name": "com.test.audit",
            "app_name": "AuditApp",
            "version_name": "1.0",
            "version_code": "1",
            "min_sdk": "21",
            "target_sdk": "33",
            "tlsh": "MOCK_TLSH_abcdef",
            "certificate_fingerprint": "mock_cert_fingerprint_123",
            "risk_score": 80,
            "findings_data": [
                {
                    "title": "Mock SMS Permission",
                    "description": "App can send SMS",
                    "severity": "HIGH",
                    "category": "Permission",
                    "evidence": "android.permission.SEND_SMS",
                    "mitre_technique_id": "T1636",
                    "confidence": 1.0
                }
            ]
        }
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # Upload APK 1
            with open("tests/fixtures/dummy.apk", "rb") as f:
                res1 = await client.post("/api/v1/samples/upload", files={"file": ("dummy1.apk", f, "application/vnd.android.package-archive")})
            sample1_id = res1.json()["id"]
            
            # Create a second dummy file so it has a different hash but remains a valid zip
            with open("tests/fixtures/dummy.apk", "rb") as f_in:
                dummy_data = f_in.read()
            with open("tests/fixtures/dummy2.apk", "wb") as f_out:
                f_out.write(dummy_data + b"junk")
            with open("tests/fixtures/dummy2.apk", "rb") as f:
                res2 = await client.post("/api/v1/samples/upload", files={"file": ("dummy2.apk", f, "application/vnd.android.package-archive")})
            sample2_id = res2.json()["id"]

            await asyncio.sleep(3) # Wait for pipeline
            
            # Check status
            st1 = await client.get(f"/api/v1/samples/{sample1_id}/status")
            print("SAMPLE 1 STATUS:", st1.json())
            
            st2 = await client.get(f"/api/v1/samples/{sample2_id}/status")
            print("SAMPLE 2 STATUS:", st2.json())
            
            # Check findings
            f1 = await client.get(f"/api/v1/samples/{sample1_id}/findings")
            print("SAMPLE 1 FINDINGS:", len(f1.json()))
            
            # Check campaigns (they should have correlated on certificate)
            camp = await client.get("/api/v1/campaigns")
            print("CAMPAIGNS:", camp.json())
            if camp.json()["total"] > 0:
                camp_id = camp.json()["items"][0]["id"]
                graph = await client.get(f"/api/v1/campaigns/{camp_id}/graph")
                print("GRAPH:", graph.json())

if __name__ == "__main__":
    asyncio.run(run_success_audit())
