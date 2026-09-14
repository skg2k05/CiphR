from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.exceptions import CiphRException, ciphr_exception_handler, global_exception_handler
from app.core.logging import logger
from app.api.routes import health
import os
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting {settings.PROJECT_NAME}...")
    yield
    logger.info(f"Shutting down {settings.PROJECT_NAME}...")

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        openapi_url=f"{settings.API_V1_STR}/openapi.json",
        lifespan=lifespan,
    )

    # CORS settings
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"], # TODO: Restrict in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add exception handlers
    app.add_exception_handler(CiphRException, ciphr_exception_handler)  # type: ignore
    app.add_exception_handler(Exception, global_exception_handler)  # type: ignore

    # Ensure upload directory exists
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    
    # Include routers
    app.include_router(health.router, prefix=settings.API_V1_STR)
    from app.api.routes import samples, campaigns
    app.include_router(samples.router, prefix=settings.API_V1_STR)
    app.include_router(campaigns.router, prefix=settings.API_V1_STR)
    
    return app

app = create_app()

