"""HemisX DAST Engine — FastAPI application entry point."""
from __future__ import annotations
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .api.router import api_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("dast-engine")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🔒 HemisX DAST Engine starting on %s:%d", settings.host, settings.port)
    logger.info("   Max concurrent requests: %d", settings.max_concurrent_requests)
    logger.info("   Request timeout: %.1fs", settings.request_timeout)
    logger.info("   Max crawl depth: %d, pages: %d", settings.max_crawl_depth, settings.max_crawl_pages)
    yield
    logger.info("🔒 HemisX DAST Engine shutting down")


app = FastAPI(
    title="HemisX DAST Engine",
    description="Dynamic Application Security Testing engine with active crawling, vulnerability detection, CVSS v3.1 scoring, and professional PDF report generation.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow Next.js dev server and production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount all API routes
app.include_router(api_router)


def start():
    """CLI entry point: python -m dast_engine.main"""
    import uvicorn
    uvicorn.run(
        "dast_engine.main:app",
        host=settings.host,
        port=settings.port,
        reload=True,
        log_level="info",
    )


if __name__ == "__main__":
    start()
