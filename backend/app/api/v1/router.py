from fastapi import APIRouter

from app.api.v1.routes.analysis import router as analysis_router
from app.api.v1.routes.ping import router as ping_router

api_router = APIRouter()
api_router.include_router(ping_router)
api_router.include_router(analysis_router)