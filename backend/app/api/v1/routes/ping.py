from fastapi import APIRouter

from app.api.v1.schemas.common import MessageResponse

router = APIRouter(prefix="/ping", tags=["ping"])


@router.get("", response_model=MessageResponse)
def ping() -> MessageResponse:
    return MessageResponse(message="pong")