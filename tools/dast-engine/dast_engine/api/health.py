"""Health-check endpoint."""
from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health():
    return {
        "status": "ok",
        "engine": "hemisx-dast",
        "version": "1.0.0",
    }
