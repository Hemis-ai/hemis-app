"""Main API router aggregating all DAST endpoint modules."""
from fastapi import APIRouter
from .scans import router as scans_router
from .findings import router as findings_router
from .reports import router as reports_router
from .health import router as health_router
from .progress import router as progress_router
from .compare import router as compare_router

api_router = APIRouter(prefix="/api/dast")

api_router.include_router(health_router, tags=["health"])
api_router.include_router(scans_router, tags=["scans"])
api_router.include_router(findings_router, tags=["findings"])
api_router.include_router(reports_router, tags=["reports"])
api_router.include_router(progress_router, tags=["progress"])
api_router.include_router(compare_router, tags=["compare"])
