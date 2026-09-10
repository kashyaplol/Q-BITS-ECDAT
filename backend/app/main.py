"""Application entry point for Q-BITS-ECDAT.

Start the server with::

    uvicorn backend.app.main:app --reload

The FastAPI app is created here and all routers are registered.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from backend.app.api.health import router as health_router
from backend.app.api.v1 import api_router
from backend.app.core.config import settings
from backend.app.core.logging import configure_logging, get_logger

# Set up logging for the whole application.
configure_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle application startup and shutdown logic."""
    logger.info("%s v%s starting up", settings.project_name, settings.version)
    yield
    logger.info("%s shutting down", settings.project_name)


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""
    app = FastAPI(
        title=settings.project_name,
        description=settings.project_description,
        version=settings.version,
        debug=settings.debug,
        lifespan=lifespan,
    )

    # Root-level health endpoint: GET /health
    app.include_router(health_router)

    # All versioned endpoints under /api/v1
    app.include_router(api_router)

    return app


# Create the app instance that uvicorn will import.
app = create_app()
