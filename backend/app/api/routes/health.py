from fastapi import APIRouter

router = APIRouter(tags=["Health"])

@router.get("/health")
async def check_health():
    return {
        "status": "ok",
        "service": "ciphR-backend"
    }
